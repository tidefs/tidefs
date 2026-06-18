// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Write dispatch integration tests for the local-filesystem layer.
//!
//! Tests the write-dispatch pipeline end-to-end:
//! create → write(offset, data) → flush → read → verify.
//! Focuses on edge cases that the FUSE write-dispatch path must handle:
//! multi-block ordering, partial-block alignment, write-read visibility
//! within the same session, overwrite truncation semantics, and
//! sequential dispatch through multiple instances on the same store.
//!
//! These tests exercise the same code path that the FUSE daemon's
//! write dispatch uses: LocalFileSystem::write_file → extent allocation
//! → object-store persistence → read_file resolution.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{
    LocalFileSystem, DEFAULT_DIRECTORY_PERMISSIONS, DEFAULT_FILE_PERMISSIONS,
};

const BLOCK_SIZE: usize = 4096;

// ── Helpers ───────────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-wd-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

/// Deterministic seeded byte sequence (0..255 cycling).
fn sequenced_bytes(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Pseudo-random byte sequence seeded by `seed`.
fn prng_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Verify two byte slices are equal, with a diagnostic message on mismatch.
fn assert_bytes_eq(got: &[u8], expected: &[u8], context: &str) {
    assert_eq!(
        got.len(),
        expected.len(),
        "{context}: length mismatch: got {} bytes, expected {}",
        got.len(),
        expected.len()
    );
    for (i, (&a, &b)) in got.iter().zip(expected.iter()).enumerate() {
        if a != b {
            panic!("{context}: byte mismatch at offset {i}: got 0x{a:02x}, expected 0x{b:02x}");
        }
    }
}

// ── 1. Multi-block ordering ───────────────────────────────────────────────

/// Write 3 contiguous blocks of sequenced data, read back, verify byte-
/// for-byte correctness and block ordering is preserved.
#[test]
fn multi_block_three_contiguous_blocks_ordering() {
    set_test_key();
    let dir = temp_dir("mb_3blk");
    let data = sequenced_bytes(BLOCK_SIZE * 3);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/three_blocks.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/three_blocks.bin", 0, &data).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/three_blocks.bin").expect("read");
        assert_bytes_eq(&got, &data, "three contiguous blocks");

        // Verify each block individually via range read.
        for blk in 0..3 {
            let start = (blk * BLOCK_SIZE) as u64;
            let chunk = fs
                .read_file_range("/three_blocks.bin", start, BLOCK_SIZE)
                .expect("read block range");
            assert_bytes_eq(
                &chunk,
                &data[start as usize..start as usize + BLOCK_SIZE],
                &format!("block {blk} range read"),
            );
        }
    }
}

/// Write 5 blocks of pseudo-random data, fsync, reopen, verify block
/// ordering survives the persistence round-trip.
#[test]
fn multi_block_five_blocks_persist_ordering() {
    set_test_key();
    let dir = temp_dir("mb_5blk");
    let seed: u64 = 0x5B10_C012DE12;
    let data = prng_bytes(seed, BLOCK_SIZE * 5);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/five_blocks.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/five_blocks.bin", 0, &data).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/five_blocks.bin").expect("read");
        assert_bytes_eq(&got, &data, "five blocks persist");

        // Spot-check block boundaries: first byte of each block.
        for blk in 0..5 {
            let offset = (blk * BLOCK_SIZE) as u64;
            let first_byte = fs
                .read_file_range("/five_blocks.bin", offset, 1)
                .expect("read first byte");
            assert_eq!(
                first_byte[0], data[offset as usize],
                "block {blk} first byte mismatch"
            );
        }
    }
}

/// Write non-contiguous blocks (skip every other block), verify the
/// gap is zero-filled and written blocks are in correct order.
#[test]
fn multi_block_non_contiguous_ordering() {
    set_test_key();
    let dir = temp_dir("mb_noncontig");
    let block0 = prng_bytes(0xA0, BLOCK_SIZE);
    let block2 = prng_bytes(0xA2, BLOCK_SIZE);
    let block4 = prng_bytes(0xA4, BLOCK_SIZE);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/skip_blocks.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/skip_blocks.bin", 0, &block0)
            .expect("write blk0");
        fs.write_file("/skip_blocks.bin", (BLOCK_SIZE * 2) as u64, &block2)
            .expect("write blk2");
        fs.write_file("/skip_blocks.bin", (BLOCK_SIZE * 4) as u64, &block4)
            .expect("write blk4");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/skip_blocks.bin").expect("read");
        let expected_size = BLOCK_SIZE * 4 + BLOCK_SIZE;
        assert_eq!(got.len(), expected_size, "non-contiguous file size");

        // Block 0: data.
        assert_bytes_eq(&got[0..BLOCK_SIZE], &block0, "block 0");
        // Block 1: zeros.
        assert!(
            got[BLOCK_SIZE..BLOCK_SIZE * 2].iter().all(|&b| b == 0),
            "block 1 zero-filled"
        );
        // Block 2: data.
        assert_bytes_eq(&got[BLOCK_SIZE * 2..BLOCK_SIZE * 3], &block2, "block 2");
        // Block 3: zeros.
        assert!(
            got[BLOCK_SIZE * 3..BLOCK_SIZE * 4].iter().all(|&b| b == 0),
            "block 3 zero-filled"
        );
        // Block 4: data.
        assert_bytes_eq(&got[BLOCK_SIZE * 4..BLOCK_SIZE * 5], &block4, "block 4");
    }
}

// ── 2. Partial-block writes (unaligned offsets/lengths) ──────────────────

/// Write at offset 0 with a partial-block length (512 bytes within a
/// 4 KiB block). Verify the read-back is exact and no extra bytes appear.
#[test]
fn partial_block_write_at_zero_short_length() {
    set_test_key();
    let dir = temp_dir("pb_zero_short");
    let data = prng_bytes(0xB00, 512);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/pb_zero.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/pb_zero.bin", 0, &data).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/pb_zero.bin").expect("read");
        assert_eq!(got.len(), data.len(), "partial-block file size");
        assert_bytes_eq(&got, &data, "partial-block start at 0");
    }
}

/// Write at an unaligned offset within the first block, verify
/// surrounding data is preserved.
#[test]
fn partial_block_write_unaligned_offset_preserves_surrounding() {
    set_test_key();
    let dir = temp_dir("pb_unaligned");
    let first = prng_bytes(0xC0, BLOCK_SIZE); // 4096 bytes at offset 0
    let overlay = prng_bytes(0xC1, 123); // 123 bytes at offset 1000
    let second = prng_bytes(0xC2, 500); // 500 bytes at offset 3000

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/unaligned.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/unaligned.bin", 0, &first)
            .expect("write first block");
        fs.write_file("/unaligned.bin", 1000, &overlay)
            .expect("write overlay");
        fs.write_file("/unaligned.bin", 3000, &second)
            .expect("write second");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/unaligned.bin").expect("read");
        let expected_size = 4096usize; // max(4096, 1000+123, 3000+500) = 4096
        assert_eq!(
            got.len(),
            expected_size,
            "unaligned file size (max of all extents)"
        );

        // Prefix before overlay (0..1000).
        assert_bytes_eq(&got[0..1000], &first[0..1000], "prefix before overlay");
        // Overlay (1000..1123).
        assert_bytes_eq(&got[1000..1123], &overlay, "overlay region");
        // Gap between overlay and second write (1123..3000).
        assert_bytes_eq(&got[1123..3000], &first[1123..3000], "gap between writes");
        // Second write (3000..3500).
        assert_bytes_eq(&got[3000..3500], &second, "second write region");
    }
}

/// Write a single byte at a large unaligned offset, verify zero-fill
/// and that the byte is correctly placed.
#[test]
fn partial_block_single_byte_at_unaligned_offset() {
    set_test_key();
    let dir = temp_dir("pb_one_byte");
    let byte_val: u8 = 0x7E;
    let offset: u64 = 7777; // unaligned, not page-aligned

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/one_byte.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/one_byte.bin", offset, &[byte_val])
            .expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/one_byte.bin").expect("read");
        assert_eq!(got.len(), (offset + 1) as usize, "one-byte file size");

        // All bytes before offset should be zero.
        assert!(
            got[..offset as usize].iter().all(|&b| b == 0),
            "prefix zero-filled"
        );
        // The byte at offset should match.
        assert_eq!(
            got[offset as usize], byte_val,
            "single byte at unaligned offset"
        );
    }
}

/// Write to an unaligned offset that spans a block boundary.
#[test]
fn partial_block_write_crossing_block_boundary() {
    set_test_key();
    let dir = temp_dir("pb_cross_boundary");
    let offset: u64 = (BLOCK_SIZE - 200) as u64; // 200 bytes before block boundary
    let data = prng_bytes(0xD0, 500); // spans across the boundary

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/cross_bound.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/cross_bound.bin", offset, &data)
            .expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/cross_bound.bin").expect("read");
        let expected_size = offset as usize + data.len();
        assert_eq!(got.len(), expected_size, "cross-boundary file size");

        // Prefix zero-filled up to offset.
        assert!(
            got[..offset as usize].iter().all(|&b| b == 0),
            "prefix zeros before offset"
        );
        // Data region.
        assert_bytes_eq(
            &got[offset as usize..],
            &data,
            "data spanning block boundary",
        );
    }
}

/// Write at unaligned offset starting from non-zero existing data,
/// verify the unaligned overlay doesn't corrupt adjacent bytes.
#[test]
fn partial_block_unaligned_overlay_on_existing_data() {
    set_test_key();
    let dir = temp_dir("pb_overlay_existing");
    let base = prng_bytes(0xE0, 4096);
    // Overlay 7 bytes at offset 511 (not aligned to anything).
    let patch = [0xAAu8, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/overlay_existing.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/overlay_existing.bin", 0, &base)
            .expect("write base");
        fs.write_file("/overlay_existing.bin", 511, &patch)
            .expect("write patch");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/overlay_existing.bin").expect("read");
        assert_eq!(got.len(), base.len(), "overlay preserves size");

        // Bytes 0..511: original.
        assert_bytes_eq(&got[0..511], &base[0..511], "prefix before patch");
        // Bytes 511..518: patch.
        assert_eq!(&got[511..518], &patch, "patch region");
        // Bytes 518..: original.
        assert_bytes_eq(&got[518..], &base[518..], "suffix after patch");
    }
}

// ── 3. Write-read visibility (no fsync, same session) ────────────────────

/// Write data then immediately read back within the same LocalFileSystem
/// instance. The write buffer or page cache should make the data visible
/// without an explicit fsync.
#[test]
fn write_read_visibility_same_instance_no_fsync() {
    set_test_key();
    let dir = temp_dir("vis_same_instance");
    let data = sequenced_bytes(2048);

    let mut fs = open_fs(&dir);
    fs.create_file("/visible.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/visible.bin", 0, &data).expect("write");

    // Read back immediately — no fsync, no reopen.
    let got = fs.read_file("/visible.bin").expect("read");
    assert_bytes_eq(&got, &data, "same-instance visibility");
}

/// Write data through one LocalFileSystem instance, sync, then read
/// through a second instance on the same store. This exercises the
/// object-store persistence path used by write dispatch.
#[test]
fn write_read_visibility_cross_instance() {
    set_test_key();
    let dir = temp_dir("vis_cross_instance");
    let data = prng_bytes(0xFACE, 1024);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/cross_vis.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/cross_vis.bin", 0, &data).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/cross_vis.bin").expect("read");
        assert_bytes_eq(&got, &data, "cross-instance visibility");
    }
}

/// Write multiple small files in rapid succession, then read all back
/// within the same instance without fsync.
///
/// Creates files at root and in a subdirectory. The subdirectory must be
/// created explicitly before files inside it can be opened.
#[test]
fn write_read_visibility_multiple_files_no_fsync() {
    set_test_key();
    let dir = temp_dir("vis_multi_file");
    let files: &[(&str, &[u8])] = &[
        ("/a.txt", b"alpha"),
        ("/b.txt", b"beta"),
        ("/c.txt", b"gamma"),
        ("/sub/d.txt", b"delta"),
    ];

    let mut fs = open_fs(&dir);
    // Create subdirectory explicitly before creating files inside it.
    fs.create_dir("/sub", DEFAULT_DIRECTORY_PERMISSIONS)
        .expect("mkdir /sub");
    for (name, content) in files {
        fs.create_file(name, DEFAULT_FILE_PERMISSIONS)
            .unwrap_or_else(|e| panic!("create {name}: {e}"));
        fs.write_file(name, 0, content)
            .unwrap_or_else(|e| panic!("write {name}: {e}"));
    }

    for (name, expected) in files {
        let got = fs
            .read_file(name)
            .unwrap_or_else(|e| panic!("read {name}: {e}"));
        assert_eq!(&got[..], *expected, "multi-file visibility for {name}");
    }
}

#[test]
fn write_read_visibility_sparse_holes() {
    set_test_key();
    let dir = temp_dir("vis_sparse");
    let head = prng_bytes(0x100, 256);
    let tail = prng_bytes(0x101, 256);
    let hole_start: u64 = 8192;

    let mut fs = open_fs(&dir);
    fs.create_file("/sparse_vis.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/sparse_vis.bin", 0, &head)
        .expect("write head");
    fs.write_file("/sparse_vis.bin", hole_start, &tail)
        .expect("write tail");

    // Read hole region — should be zero-filled.
    let hole = fs
        .read_file_range("/sparse_vis.bin", 256, 256)
        .expect("read hole");
    assert!(
        hole.iter().all(|&b| b == 0),
        "sparse hole zero-filled without fsync"
    );

    // Read head.
    let got_head = fs
        .read_file_range("/sparse_vis.bin", 0, 256)
        .expect("read head range");
    assert_bytes_eq(&got_head, &head, "sparse head");

    // Read tail.
    let got_tail = fs
        .read_file_range("/sparse_vis.bin", hole_start, 256)
        .expect("read tail range");
    assert_bytes_eq(&got_tail, &tail, "sparse tail");
}

// ── 4. Overwrite truncation ───────────────────────────────────────────────

/// Write a full block, then write a shorter payload at offset 0.
/// The file should be truncated to the shorter length with no stale
/// data leaking past the new end.
#[test]
fn overwrite_truncation_shorter_at_zero() {
    set_test_key();
    let dir = temp_dir("ot_shorter");
    let original = prng_bytes(0xDEAD, 4096);
    let shorter = prng_bytes(0xBEEF, 1024);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/trunc_ow.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/trunc_ow.bin", 0, &original)
            .expect("write original");

        // Overwrite with shorter data at offset 0, then explicitly truncate.
        fs.write_file("/trunc_ow.bin", 0, &shorter)
            .expect("write shorter");
        // Flush write buffers so truncate_file sees the real inode size.
        fs.flush_all_write_buffers().expect("flush");
        fs.truncate_file("/trunc_ow.bin", shorter.len() as u64)
            .expect("truncate to shorter length");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/trunc_ow.bin").expect("read");
        let stat_size = fs.stat("/trunc_ow.bin").unwrap().size;

        // After explicit truncate, the file should contain exactly the
        // shorter data — no stale tail.
        assert_eq!(
            got.len(),
            shorter.len(),
            "truncation: read length should match shorter write"
        );
        assert_eq!(
            stat_size,
            shorter.len() as u64,
            "truncation: stat size should match shorter write"
        );
        assert_bytes_eq(&got, &shorter, "overwrite + truncate content");
    }
}

#[test]
fn overwrite_truncation_large_to_small() {
    set_test_key();
    let dir = temp_dir("ot_large_small");
    let large = sequenced_bytes(BLOCK_SIZE * 4); // 16 KiB
    let small = prng_bytes(0xCAFE, 13); // tiny

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/large_to_small.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/large_to_small.bin", 0, &large)
            .expect("write large");
        // Overwrite front with tiny data, then truncate to commit the shrink.
        fs.write_file("/large_to_small.bin", 0, &small)
            .expect("write small");
        fs.flush_all_write_buffers().expect("flush");
        fs.truncate_file("/large_to_small.bin", small.len() as u64)
            .expect("truncate to small");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/large_to_small.bin").expect("read");
        assert_eq!(
            got.len(),
            small.len(),
            "large-to-small: length should be {} bytes",
            small.len()
        );
        assert_bytes_eq(&got, &small, "large-to-small content after truncate");
    }
}

/// Write data, then write a different payload at the same offset with
/// the same length. Verify the file is correctly replaced (no truncation
/// needed, but verify no corruption).
#[test]
fn overwrite_same_length_replacement() {
    set_test_key();
    let dir = temp_dir("ot_same_len");
    let first = prng_bytes(0x1111, 2048);
    let second = prng_bytes(0x2222, 2048);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/same_len.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/same_len.bin", 0, &first)
            .expect("write first");
        fs.write_file("/same_len.bin", 0, &second)
            .expect("write second");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/same_len.bin").expect("read");
        assert_eq!(got.len(), 2048, "same-length replacement size unchanged");
        assert_bytes_eq(&got, &second, "same-length replacement content");
    }
}

/// Write at offset 0, then write shorter at offset 0, then write longer
/// at offset 0. Each should reflect the current state correctly.
#[test]
fn overwrite_truncation_then_expand() {
    set_test_key();
    let dir = temp_dir("ot_expand");
    let a = prng_bytes(0xA1, 4096);
    let b = prng_bytes(0xB1, 512);
    let c = prng_bytes(0xC1, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/expand_contract.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");

    // Write A (4096 bytes).
    fs.write_file("/expand_contract.bin", 0, &a)
        .expect("write A");
    fs.flush_all_write_buffers().expect("flush");
    assert_eq!(fs.stat("/expand_contract.bin").unwrap().size, 4096);
    assert_bytes_eq(
        &fs.read_file("/expand_contract.bin").unwrap(),
        &a,
        "after A",
    );

    // Write B (512 bytes) at offset 0, then truncate explicitly.
    fs.write_file("/expand_contract.bin", 0, &b)
        .expect("write B");
    fs.flush_all_write_buffers().expect("flush");
    fs.truncate_file("/expand_contract.bin", b.len() as u64)
        .expect("truncate to B length");
    assert_eq!(fs.stat("/expand_contract.bin").unwrap().size, 512);
    let after_b = fs.read_file("/expand_contract.bin").unwrap();
    assert_bytes_eq(&after_b, &b, "after B + truncate");

    // Write C (8192 bytes) at offset 0 — extends past B.
    fs.write_file("/expand_contract.bin", 0, &c)
        .expect("write C");
    fs.flush_all_write_buffers().expect("flush");
    assert_eq!(fs.stat("/expand_contract.bin").unwrap().size, 8192);
    let after_c = fs.read_file("/expand_contract.bin").unwrap();
    assert_bytes_eq(&after_c, &c, "after C (expand)");

    fs.sync_all().expect("sync");
}

// ── 5. Sequential dispatch through multiple store instances ───────────────

/// Open two sequential LocalFileSystem instances on the same store.
/// Write through the first, sync, then write through the second and
/// verify both writes survive. This simulates the FUSE daemon restarting
/// and continuing to write to the same files.
#[test]
fn sequential_dispatch_across_instances() {
    set_test_key();
    let dir = temp_dir("seq_dispatch");
    let first_data = prng_bytes(0x5E0, 1024);
    let second_data = prng_bytes(0x5E1, 2048);

    // Instance 1: create file, write initial data.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/seq.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/seq.bin", 0, &first_data)
            .expect("first write");
        fs.sync_all().expect("sync");
    }

    // Instance 2: reopen, append more data.
    {
        let mut fs = open_fs(&dir);
        let existing = fs.read_file("/seq.bin").expect("read existing");
        assert_bytes_eq(&existing, &first_data, "existing data before append");

        fs.write_file("/seq.bin", first_data.len() as u64, &second_data)
            .expect("append write");
        fs.sync_all().expect("sync");
    }

    // Instance 3: verify both writes.
    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/seq.bin").expect("read final");
        let mut expected = first_data.clone();
        expected.extend_from_slice(&second_data);
        assert_bytes_eq(&got, &expected, "sequential dispatch both writes");
    }
}

/// Write to many files through one instance, sync, then open a new
/// instance and verify all files are intact.
#[test]
fn sequential_dispatch_many_files_across_instances() {
    set_test_key();
    let dir = temp_dir("seq_many");
    let count = 20;
    let mut expected: Vec<(String, Vec<u8>)> = Vec::with_capacity(count);

    {
        let mut fs = open_fs(&dir);
        for i in 0..count {
            let name = format!("/file_{i:02}.bin");
            let data = prng_bytes(i as u64, 256 + i * 13);
            fs.create_file(&name, DEFAULT_FILE_PERMISSIONS)
                .unwrap_or_else(|e| panic!("create {name}: {e}"));
            fs.write_file(&name, 0, &data)
                .unwrap_or_else(|e| panic!("write {name}: {e}"));
            expected.push((name, data));
        }
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        for (name, data) in &expected {
            let got = fs
                .read_file(name)
                .unwrap_or_else(|e| panic!("read {name}: {e}"));
            assert_bytes_eq(&got, data, &format!("seq many: {name}"));
        }
    }
}

// ── 6. Overwrite with partial overlap of existing extents ─────────────────

/// Write extent A at [0, 4096), then write extent B at [2048, 6144).
/// Verify the overlap is handled correctly and the resulting file is
/// A[0..2048] + B[0..4096] = 6144 bytes.
#[test]
fn overwrite_partial_extent_overlap() {
    set_test_key();
    let dir = temp_dir("ow_ext_overlap");
    let a = prng_bytes(0xA0, BLOCK_SIZE); // 4096 bytes
    let b = prng_bytes(0xB0, BLOCK_SIZE); // 4096 bytes

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/overlap.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/overlap.bin", 0, &a).expect("write A");
        fs.write_file("/overlap.bin", 2048, &b)
            .expect("write B overlapping");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/overlap.bin").expect("read");
        let expected_size = 2048 + BLOCK_SIZE; // 6144
        assert_eq!(got.len(), expected_size, "overlap extent file size");

        // First 2048 bytes: from A.
        assert_bytes_eq(&got[0..2048], &a[0..2048], "A prefix");
        // Bytes 2048..6144: from B.
        assert_bytes_eq(&got[2048..6144], &b, "B overlay + extension");
    }
}

/// Write extent A at [4096, 8192), then write extent B at [0, 4096).
/// Verify A is preserved and B fills the leading gap.
#[test]
fn overwrite_extent_before_existing() {
    set_test_key();
    let dir = temp_dir("ow_ext_before");
    let a = prng_bytes(0xCA, BLOCK_SIZE); // at offset 4096
    let b = prng_bytes(0xCB, BLOCK_SIZE); // at offset 0

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/before.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/before.bin", 4096, &a)
            .expect("write A at 4096");
        fs.write_file("/before.bin", 0, &b).expect("write B at 0");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let got = fs.read_file("/before.bin").expect("read");
        assert_eq!(got.len(), 8192, "extent-before file size");
        assert_bytes_eq(&got[0..4096], &b, "B at offset 0");
        assert_bytes_eq(&got[4096..8192], &a, "A at offset 4096");
    }
}

// ── 7. Concurrent write dispatch (distinct files) ────────────────────────

/// Spawn N threads sharing a single LocalFileSystem instance via
/// Arc<Mutex<>>, writing to distinct files concurrently. After all
/// threads join, verify every file is byte-correct.
#[test]
fn concurrent_write_dispatch_distinct_files() {
    set_test_key();
    let dir = temp_dir("conc_distinct");
    let n_threads: usize = 8;
    let files: Vec<(String, Vec<u8>)> = (0..n_threads)
        .map(|i| {
            let name = format!("/conc_{i:02}.bin");
            let data = prng_bytes(i as u64, 512 + i * 37);
            (name, data)
        })
        .collect();

    let fs = std::sync::Arc::new(std::sync::Mutex::new(open_fs(&dir)));
    let files_arc = std::sync::Arc::new(files);
    let mut handles = Vec::new();

    for tid in 0..n_threads {
        let fs = fs.clone();
        let f = files_arc.clone();
        handles.push(std::thread::spawn(move || {
            let mut fs = fs.lock().expect("lock");
            let (ref name, ref data) = f[tid];
            fs.create_file(name, DEFAULT_FILE_PERMISSIONS)
                .unwrap_or_else(|e| panic!("thread {tid} create {name}: {e}"));
            fs.write_file(name, 0, data)
                .unwrap_or_else(|e| panic!("thread {tid} write {name}: {e}"));
            // Don't sync here — let the final verification instance
            // handle persistence. Drop lock before join.
        }));
    }

    for h in handles {
        h.join().expect("thread join");
    }

    // Flush and sync through the shared instance.
    {
        let mut fs = fs.lock().expect("lock");
        fs.sync_all().expect("final sync");
    }

    // Final verification through a fresh instance.
    let fs = open_fs(&dir);
    for (name, data) in files_arc.iter() {
        let got = fs
            .read_file(name)
            .unwrap_or_else(|e| panic!("verify read {name}: {e}"));
        assert_bytes_eq(&got, data, &format!("concurrent distinct {name}"));
    }
}

/// Concurrent write to distinct files with overlapping allocations
/// (same block ranges). Exercises extent allocator serialisation
/// through the shared Mutex.
#[test]
fn concurrent_write_dispatch_overlapping_allocations() {
    set_test_key();
    let dir = temp_dir("conc_overlap_alloc");
    let n_threads: usize = 6;

    let fs = std::sync::Arc::new(std::sync::Mutex::new(open_fs(&dir)));

    let mut handles = Vec::new();
    for tid in 0..n_threads {
        let fs = fs.clone();
        handles.push(std::thread::spawn(move || {
            let mut fs = fs.lock().expect("lock");
            let name = format!("/overlap_{tid:02}.bin");
            let data = prng_bytes(tid as u64, BLOCK_SIZE * 3);
            fs.create_file(&name, DEFAULT_FILE_PERMISSIONS)
                .unwrap_or_else(|e| panic!("thread {tid} create: {e}"));
            fs.write_file(&name, 0, &data)
                .unwrap_or_else(|e| panic!("thread {tid} write: {e}"));
            (name, data)
        }));
    }

    let mut results: Vec<(String, Vec<u8>)> = Vec::new();
    for h in handles {
        results.push(h.join().expect("thread join"));
    }

    // Sync through shared instance.
    {
        let mut fs = fs.lock().expect("lock");
        fs.sync_all().expect("final sync");
    }

    let fs = open_fs(&dir);
    for (name, data) in &results {
        let got = fs
            .read_file(name)
            .unwrap_or_else(|e| panic!("verify read {name}: {e}"));
        assert_bytes_eq(&got, data, &format!("concurrent overlap alloc {name}"));
    }
}

/// Concurrent write + read interleaving: one writer and one reader
/// operating on separate files through the shared instance, verifying
/// no cross-contamination.
#[test]
fn concurrent_write_read_no_cross_contamination() {
    set_test_key();
    let dir = temp_dir("conc_no_cross");
    let writer_data = prng_bytes(0xD1, 4096);
    let reader_content = sequenced_bytes(2048);

    // Pre-create both files.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/writer_file.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create writer file");
        fs.create_file("/reader_file.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create reader file");
        fs.write_file("/reader_file.bin", 0, &reader_content)
            .expect("write reader content");
        fs.sync_all().expect("sync initial");
    }

    let fs = std::sync::Arc::new(std::sync::Mutex::new(open_fs(&dir)));
    let writer_data_clone = writer_data.clone();
    let reader_content_clone = reader_content.clone();

    let fs_w = fs.clone();
    let writer = std::thread::spawn(move || {
        let mut fs = fs_w.lock().expect("writer lock");
        fs.write_file("/writer_file.bin", 0, &writer_data_clone)
            .expect("writer write");
        fs.sync_all().expect("writer sync");
    });

    let fs_r = fs.clone();
    let reader = std::thread::spawn(move || {
        // Repeatedly read the reader file; should remain stable.
        for _ in 0..10 {
            let fs = fs_r.lock().expect("reader lock");
            let got = fs.read_file("/reader_file.bin").expect("reader read");
            assert_bytes_eq(
                &got,
                &reader_content_clone,
                "reader file stable during writer",
            );
        }
    });

    writer.join().expect("writer join");
    reader.join().expect("reader join");

    // Final verification.
    let fs = open_fs(&dir);
    let got_writer = fs.read_file("/writer_file.bin").expect("final read writer");
    assert_bytes_eq(&got_writer, &writer_data, "writer file after concurrent");

    let got_reader = fs.read_file("/reader_file.bin").expect("final read reader");
    assert_bytes_eq(&got_reader, &reader_content, "reader file after concurrent");
}

// ── 8. Concurrent same-file writes (serialised via shared Mutex) ────────

/// Two threads write to the same file at offset 0 through a shared
/// LocalFileSystem wrapped in a Mutex. The Mutex serialises access,
/// so the last writer to acquire the lock "wins". This verifies no
/// corruption from interleaved write_file calls.
#[test]
fn concurrent_same_file_last_writer_wins() {
    set_test_key();
    let dir = temp_dir("conc_same_file");
    let writer_a_data = prng_bytes(0xAAA, 512);
    let writer_b_data = prng_bytes(0xBBB, 512);

    // Pre-create the file.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/shared.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create shared file");
    }

    let fs = std::sync::Arc::new(std::sync::Mutex::new(open_fs(&dir)));
    let a_data = writer_a_data.clone();
    let b_data = writer_b_data.clone();

    let fs_a = fs.clone();
    let writer_a = std::thread::spawn(move || {
        // Small delay increases chance writer_b goes last.
        std::thread::sleep(std::time::Duration::from_millis(20));
        let mut fs = fs_a.lock().expect("writer_a lock");
        fs.write_file("/shared.bin", 0, &a_data)
            .expect("writer_a write");
        fs.sync_all().expect("writer_a sync");
    });

    let fs_b = fs.clone();
    let writer_b = std::thread::spawn(move || {
        let mut fs = fs_b.lock().expect("writer_b lock");
        fs.write_file("/shared.bin", 0, &b_data)
            .expect("writer_b write");
        fs.sync_all().expect("writer_b sync");
    });

    writer_a.join().expect("writer_a join");
    writer_b.join().expect("writer_b join");

    let fs = open_fs(&dir);
    let got = fs.read_file("/shared.bin").expect("read shared");
    let is_a = got.as_slice() == writer_a_data.as_slice();
    let is_b = got.as_slice() == writer_b_data.as_slice();
    assert!(
        is_a || is_b,
        "same-file concurrent write: content is neither writer_a's nor writer_b's \
         (length={}, expected {} or {})",
        got.len(),
        writer_a_data.len(),
        writer_b_data.len(),
    );
}

/// Three threads append to the same file at non-overlapping offsets
/// through a shared Mutex-wrapped instance. All data should survive.
#[test]
fn concurrent_same_file_non_overlapping_appends() {
    set_test_key();
    let dir = temp_dir("conc_append");
    let a_data = prng_bytes(0xA10, 1024);
    let b_data = prng_bytes(0xB10, 1024);
    let c_data = prng_bytes(0xC10, 1024);

    // Pre-create the file.
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/append_shared.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create append file");
    }

    let fs = std::sync::Arc::new(std::sync::Mutex::new(open_fs(&dir)));
    let da = a_data.clone();
    let db = b_data.clone();
    let dc = c_data.clone();

    let fs_a = fs.clone();
    let ta = std::thread::spawn(move || {
        let mut fs = fs_a.lock().expect("lock a");
        fs.write_file("/append_shared.bin", 0, &da)
            .expect("append a");
        fs.sync_all().expect("sync a");
    });
    let fs_b = fs.clone();
    let tb = std::thread::spawn(move || {
        let mut fs = fs_b.lock().expect("lock b");
        fs.write_file("/append_shared.bin", 1024, &db)
            .expect("append b");
        fs.sync_all().expect("sync b");
    });
    let fs_c = fs.clone();
    let tc = std::thread::spawn(move || {
        let mut fs = fs_c.lock().expect("lock c");
        fs.write_file("/append_shared.bin", 2048, &dc)
            .expect("append c");
        fs.sync_all().expect("sync c");
    });

    ta.join().expect("join a");
    tb.join().expect("join b");
    tc.join().expect("join c");

    let fs = open_fs(&dir);
    let got = fs
        .read_file("/append_shared.bin")
        .expect("read append shared");
    assert_eq!(got.len(), 3072, "non-overlapping append: total length");

    // Each region should match, order-independent thanks to sync_all ordering.
    let a_ok = got[0..1024] == a_data[..]
        || got[1024..2048] == a_data[..]
        || got[2048..3072] == a_data[..];
    let b_ok = got[0..1024] == b_data[..]
        || got[1024..2048] == b_data[..]
        || got[2048..3072] == b_data[..];
    let c_ok = got[0..1024] == c_data[..]
        || got[1024..2048] == c_data[..]
        || got[2048..3072] == c_data[..];
    assert!(a_ok, "append: writer_a data appears somewhere");
    assert!(b_ok, "append: writer_b data appears somewhere");
    assert!(c_ok, "append: writer_c data appears somewhere");
}
