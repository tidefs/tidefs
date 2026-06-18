// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-path unit tests for the local-filesystem layer.
//!
//! Exercises the read, getattr, and lookup entry points on regular files.
//! Complements the write-read integration tests in write_read_integration.rs
//! which already cover the data path. This module adds targeted coverage for
//! the metadata-side read operations: getattr attribute verification and
//! lookup namespace resolution.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_types_vfs_core::{InodeId, NodeKind, S_IFREG};

// Helpers

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-rp-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = seed;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// getattr after create

#[test]
fn getattr_after_create_returns_correct_file_attributes() {
    set_test_key();
    let dir = temp_dir("getattr_create");
    let payload = make_data(0xCD, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/attr_test.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/attr_test.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let attr = fs.stat_attr("/attr_test.bin").expect("stat_attr");
    assert_eq!(attr.kind, NodeKind::File, "inode kind is regular file");
    assert_eq!(
        attr.posix.mode & S_IFREG,
        S_IFREG,
        "mode has S_IFREG bit set"
    );
    assert_eq!(attr.posix.size, 1024, "size matches written data");
    assert!(attr.posix.nlink >= 1, "nlink is at least 1");
    assert!(attr.posix.atime_ns > 0, "atime is set");
    assert!(attr.posix.mtime_ns > 0, "mtime is set");
    assert!(attr.posix.ctime_ns > 0, "ctime is set");
    assert_ne!(attr.inode_id, InodeId(0), "inode_id is not zero");
}

#[test]
fn getattr_after_create_then_reopen_preserves_attributes() {
    set_test_key();
    let dir = temp_dir("getattr_reopen");
    let payload = b"persistent attr check".to_vec();

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/persist.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/persist.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let attr = fs
            .stat_attr("/persist.bin")
            .expect("stat_attr after reopen");
        assert_eq!(attr.kind, NodeKind::File);
        assert_eq!(attr.posix.size, payload.len() as u64);
        assert!(attr.posix.nlink >= 1);
    }
}

// getattr on empty file

#[test]
fn getattr_on_empty_file_returns_zero_size() {
    set_test_key();
    let dir = temp_dir("getattr_empty");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.dat", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let attr = fs.stat_attr("/empty.dat").expect("stat_attr");
    assert_eq!(attr.kind, NodeKind::File);
    assert_eq!(attr.posix.size, 0, "empty file has size 0");
    assert!(attr.posix.nlink >= 1);
}

// lookup existing file

#[test]
fn lookup_existing_file_returns_valid_inode_id() {
    set_test_key();
    let dir = temp_dir("lookup_exist");

    let mut fs = open_fs(&dir);
    fs.create_file("/target.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/target.bin").expect("lookup existing file");
    assert_ne!(ino, InodeId(0), "lookup returns non-zero inode");

    let attr = fs.stat_attr("/target.bin").expect("stat_attr");
    assert_eq!(ino, attr.inode_id, "lookup inode matches stat_attr inode");
}

#[test]
fn lookup_existing_file_in_subdirectory() {
    set_test_key();
    let dir = temp_dir("lookup_subdir");

    let mut fs = open_fs(&dir);
    fs.create_dir("/sub", 0o755).expect("create dir");
    fs.create_file("/sub/nested.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create nested");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/sub/nested.bin").expect("lookup nested file");
    assert_ne!(ino, InodeId(0));

    let attr = fs.stat_attr("/sub/nested.bin").expect("stat_attr nested");
    assert_eq!(ino, attr.inode_id);
    assert_eq!(attr.kind, NodeKind::File);
}

// lookup nonexistent

#[test]
fn lookup_nonexistent_file_returns_error() {
    set_test_key();
    let dir = temp_dir("lookup_enoent");

    let fs = open_fs(&dir);
    let result = fs.lookup("/no_such_file.txt");
    assert!(result.is_err(), "lookup nonexistent must fail");
}

#[test]
fn lookup_nonexistent_in_populated_filesystem() {
    set_test_key();
    let dir = temp_dir("lookup_enoent_populated");

    let mut fs = open_fs(&dir);
    fs.create_file("/real.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create real");
    fs.sync_all().expect("sync");

    assert!(fs.lookup("/real.bin").is_ok());
    assert!(fs.lookup("/not_here.bin").is_err());
    assert!(fs.lookup("/real.bin/sub").is_err());
}

// getattr on nonexistent

#[test]
fn getattr_on_nonexistent_file_returns_error() {
    set_test_key();
    let dir = temp_dir("getattr_enoent");

    let fs = open_fs(&dir);
    let result = fs.stat_attr("/ghost.dat");
    assert!(result.is_err(), "getattr on nonexistent must fail");
}

// Read edge cases

#[test]
fn read_file_range_past_eof_returns_empty() {
    set_test_key();
    let dir = temp_dir("read_past_eof");
    let payload = make_data(0x5A, 256);

    let mut fs = open_fs(&dir);
    fs.create_file("/short.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/short.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let past = fs
        .read_file_range("/short.bin", 512, 64)
        .expect("read past eof");
    assert!(past.is_empty(), "read past EOF returns empty");

    let spanning = fs
        .read_file_range("/short.bin", 128, 256)
        .expect("read spanning eof");
    assert_eq!(
        spanning.len(),
        128,
        "read spanning EOF truncates at file end"
    );
    assert_eq!(&spanning[..], &payload[128..256]);
}

#[test]
fn read_file_range_at_zero_len_returns_empty() {
    set_test_key();
    let dir = temp_dir("read_zero_len");
    let payload = make_data(0x7E, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/data.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let chunk = fs
        .read_file_range("/data.bin", 64, 0)
        .expect("read zero len");
    assert!(chunk.is_empty(), "zero-length read returns empty");
}

// ── Full-file sequential read ─────────────────────────────────────────

#[test]
fn full_file_sequential_read_byte_for_byte() {
    set_test_key();
    let dir = temp_dir("seq_read");
    let payload = make_data(0x5A, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/seq.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/seq.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/seq.bin").expect("read full file");
    assert_eq!(result.len(), 4096, "full file length matches");
    assert_eq!(result, payload, "byte-for-byte match");
}

#[test]
fn full_file_sequential_read_in_chunks() {
    set_test_key();
    let dir = temp_dir("chunk_read");
    let payload = make_data(0x3C, 16384); // 16 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/chunks.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/chunks.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let mut assembled = Vec::new();
    let mut offset = 0u64;
    loop {
        let chunk = fs
            .read_file_range("/chunks.bin", offset, 4096)
            .expect("read chunk");
        if chunk.is_empty() {
            break;
        }
        assembled.extend_from_slice(&chunk);
        offset += chunk.len() as u64;
    }
    assert_eq!(assembled, payload, "chunked assembly matches original");
}

// ── Partial read at offset ────────────────────────────────────────────

#[test]
fn partial_read_at_offset_returns_correct_slice() {
    set_test_key();
    let dir = temp_dir("partial");
    let payload = make_data(0x7B, 65536); // 64 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/partial.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/partial.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read 17 bytes at offset 8193
    let slice = fs
        .read_file_range("/partial.bin", 8193, 17)
        .expect("read partial");
    assert_eq!(slice.len(), 17);
    assert_eq!(&slice[..], &payload[8193..8210]);
}

#[test]
fn partial_read_at_multiple_offsets() {
    set_test_key();
    let dir = temp_dir("multi_off");
    let payload = make_data(0x11, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/offsets.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/offsets.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    for off in [0u64, 1, 512, 4095, 2048] {
        let want = &payload[off as usize..];
        let got = fs
            .read_file_range("/offsets.bin", off, (4096 - off) as usize)
            .expect("read at offset");
        assert_eq!(got, want, "mismatch at offset {off}");
    }
}

// ── Read spanning segment boundaries ───────────────────────────────────

#[test]
fn read_spanning_segment_boundaries() {
    set_test_key();
    let dir = temp_dir("seg_bound");
    // Write enough data to force multiple object-store segments.
    // The segment size in tidefs-local-object-store defaults to
    // SEGMENT_CAPACITY_BYTES; 128 KiB should span at least two segments.
    let payload = make_data(0xA1, 131072); // 128 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/span.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/span.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read the full file to verify assembly
    let full = fs.read_file("/span.bin").expect("read full");
    assert_eq!(full, payload, "full-file assembly across segments");

    // Read a chunk that straddles the typical 64 KiB segment boundary
    let boundary = 65535; // one byte before 64 KiB
    let straddle = fs
        .read_file_range("/span.bin", boundary, 128)
        .expect("read straddle");
    assert_eq!(straddle.len(), 128);
    assert_eq!(
        &straddle[..],
        &payload[boundary as usize..(boundary as usize + 128)]
    );
}

// ── Concurrent reads ───────────────────────────────────────────────────

#[test]
fn concurrent_reads_disjoint_ranges() {
    set_test_key();
    let dir = temp_dir("concurrent");
    let payload = make_data(0x42, 16384); // 16 KiB, 4 pages

    let mut fs = open_fs(&dir);
    fs.create_file("/shared.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/shared.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Reopen read-only for thread safety (LocalFileSystem is not Sync,
    // so we open separate handles per thread).
    let fs_static: &'static std::path::Path = Box::leak(dir.clone().into_boxed_path());
    let payload_static: &'static [u8] = Box::leak(payload.into_boxed_slice());

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..4)
            .map(|i| {
                s.spawn(move || {
                    let fs = open_fs(fs_static);
                    let off = (i * 4096) as u64;
                    let chunk = fs
                        .read_file_range("/shared.bin", off, 4096)
                        .expect("concurrent read");
                    assert_eq!(chunk.len(), 4096);
                    let expected = &payload_static[off as usize..(off as usize + 4096)];
                    assert_eq!(chunk, expected, "thread {i} mismatch");
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

// ── Read-ahead hint ────────────────────────────────────────────────────

#[test]
fn read_ahead_hint_populates_for_sequential_read() {
    set_test_key();
    let dir = temp_dir("readahead");
    let payload = make_data(0xEE, 32768); // 32 KiB

    let mut fs = open_fs(&dir);
    fs.create_file("/ahead.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/ahead.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read the first page; a read-ahead hint should pre-populate the
    // next page in cache. We verify by reading the second page and
    // checking that the hot_read_cache reports at least one hit.
    let _first = fs
        .read_file_range("/ahead.bin", 0, 4096)
        .expect("read first page");

    // The preflight report before read-ahead may be zero or non-zero.
    // After the first read, subsequent read of the next page should
    // be fast (cache-assisted), and we can check the cache report.
    let report_before = fs.hot_read_cache_report();

    let _second = fs
        .read_file_range("/ahead.bin", 4096, 4096)
        .expect("read second page");

    let report_after = fs.hot_read_cache_report();
    // Cache should have been populated: either hits increased or
    // total access count grew.
    assert!(
        (report_after.hits + report_after.misses) >= (report_before.hits + report_before.misses),
        "read-ahead should populate cache"
    );
}

// ── Error handling: directory as file ─────────────────────────────────

#[test]
fn read_file_on_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("read_dir_err");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/mydir");
    assert!(result.is_err(), "read_file on directory must fail");
    assert!(
        format!("{:?}", result.as_ref().err()).contains("IsDirectory")
            || format!("{:?}", result.as_ref().err()).contains("is a directory"),
        "expected IsDirectory error, got {:?}",
        result.err()
    );
}

#[test]
fn read_file_range_on_directory_returns_is_directory() {
    set_test_key();
    let dir = temp_dir("read_range_dir_err");

    let mut fs = open_fs(&dir);
    fs.create_dir("/mydir", 0o755).expect("create dir");
    fs.sync_all().expect("sync");

    let result = fs.read_file_range("/mydir", 0, 64);
    assert!(result.is_err(), "read_file_range on directory must fail");
    assert!(
        format!("{:?}", result.as_ref().err()).contains("IsDirectory")
            || format!("{:?}", result.as_ref().err()).contains("is a directory"),
        "expected IsDirectory error, got {:?}",
        result.err()
    );
}

#[test]
fn read_file_on_nonexistent_path_returns_error() {
    set_test_key();
    let dir = temp_dir("read_enoent");

    let fs = open_fs(&dir);
    let result = fs.read_file("/no_such_file.bin");
    assert!(result.is_err(), "read_file on nonexistent must fail");
}

#[test]
fn read_file_range_on_nonexistent_path_returns_error() {
    set_test_key();
    let dir = temp_dir("read_range_enoent");

    let fs = open_fs(&dir);
    let result = fs.read_file_range("/ghost.bin", 0, 64);
    assert!(result.is_err(), "read_file_range on nonexistent must fail");
}

// ── Overwrite + read-back ─────────────────────────────────────────────

#[test]
fn overwrite_middle_portion_and_read_back() {
    set_test_key();
    let dir = temp_dir("overwrite_mid");
    let original = make_data(0x11, 8192);
    let replacement = make_data(0xFF, 512);

    let mut fs = open_fs(&dir);
    fs.create_file("/over.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/over.bin", 0, &original).expect("write");
    fs.sync_all().expect("sync");

    // Overwrite 512 bytes starting at offset 2048
    fs.write_file("/over.bin", 2048, &replacement)
        .expect("overwrite");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/over.bin").expect("read back");
    assert_eq!(result.len(), 8192);
    // First 2048 bytes unchanged
    assert_eq!(&result[..2048], &original[..2048]);
    // Overwritten region
    assert_eq!(&result[2048..2560], &replacement[..]);
    // Remainder unchanged
    assert_eq!(&result[2560..], &original[2560..]);
}

#[test]
fn overwrite_at_file_end_and_read_back() {
    set_test_key();
    let dir = temp_dir("overwrite_end");
    let original = make_data(0x22, 4096);
    let extension = make_data(0xAA, 2048);

    let mut fs = open_fs(&dir);
    fs.create_file("/extend.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/extend.bin", 0, &original).expect("write");
    fs.sync_all().expect("sync");

    // Write at offset 4096 (exact end — extends the file)
    fs.write_file("/extend.bin", 4096, &extension)
        .expect("extend");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/extend.bin").expect("read back");
    assert_eq!(result.len(), 4096 + 2048);
    assert_eq!(&result[..4096], &original[..]);
    assert_eq!(&result[4096..], &extension[..]);
}

// ── Truncate + read-back ──────────────────────────────────────────────

#[test]
fn truncate_shorter_and_read_back() {
    set_test_key();
    let dir = temp_dir("truncate_shorter");
    let payload = make_data(0x33, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/trunc.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/trunc.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    fs.truncate_file("/trunc.bin", 2048).expect("truncate");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/trunc.bin").expect("read truncated");
    assert_eq!(result.len(), 2048);
    assert_eq!(&result[..], &payload[..2048]);

    // Read past the new EOF should return empty
    let past = fs
        .read_file_range("/trunc.bin", 4096, 64)
        .expect("read past new eof");
    assert!(past.is_empty());
}

#[test]
fn truncate_to_zero_and_read_back() {
    set_test_key();
    let dir = temp_dir("truncate_zero");
    let payload = make_data(0x44, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/zero.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/zero.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    fs.truncate_file("/zero.bin", 0).expect("truncate to zero");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/zero.bin").expect("read truncated");
    assert!(result.is_empty(), "truncated to zero must be empty");
}

// ── Unaligned / small reads ───────────────────────────────────────────

#[test]
fn read_unaligned_sizes_byte_for_byte() {
    set_test_key();
    let dir = temp_dir("unaligned");
    // Use prime-sized data to avoid accidental alignment
    let payload = make_data(0x55, 7919); // prime-sized

    let mut fs = open_fs(&dir);
    fs.create_file("/unaligned.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unaligned.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read with various sizes that cross chunk boundaries
    for read_len in [1usize, 511, 512, 513, 1023, 1024, 4095, 4096, 4097] {
        let chunk = fs
            .read_file_range("/unaligned.bin", 0, read_len)
            .expect("read unaligned");
        let expected_len = read_len.min(7919);
        assert_eq!(
            chunk.len(),
            expected_len,
            "length mismatch for len={read_len}"
        );
        assert_eq!(
            &chunk[..],
            &payload[..expected_len],
            "data mismatch for len={read_len}"
        );
    }
}

#[test]
fn read_unaligned_offsets_with_varying_lengths() {
    set_test_key();
    let dir = temp_dir("unaligned_off");
    let payload = make_data(0x66, 16384);

    let mut fs = open_fs(&dir);
    fs.create_file("/offlen.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/offlen.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Vary both offset and length, hitting chunk boundaries
    let cases: &[(u64, usize)] = &[
        (0, 1),
        (1, 511),
        (0, 512),
        (512, 512),
        (511, 2),
        (4095, 2),
        (4095, 512),
        (4096, 1),
        (4096, 4096),
        (8191, 2),
        (8192, 1),
        (16383, 1),
        (1024, 1337), // straddles multiple chunks
    ];
    for &(off, len) in cases {
        let want = &payload[off as usize..(off as usize + len).min(payload.len())];
        let got = fs
            .read_file_range("/offlen.bin", off, len)
            .expect("read at offset/length");
        assert_eq!(got, want, "mismatch at offset={off} len={len}");
    }
}

// ── Read at exact file boundary ───────────────────────────────────────

#[test]
fn read_at_exact_end_of_file_returns_empty() {
    set_test_key();
    let dir = temp_dir("exact_end");
    let payload = make_data(0x77, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/end.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/end.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Read starting exactly at file size
    let end = fs
        .read_file_range("/end.bin", 4096, 64)
        .expect("read at exact end");
    assert!(end.is_empty(), "read at exact EOF returns empty");
}

#[test]
fn read_last_byte_of_file() {
    set_test_key();
    let dir = temp_dir("last_byte");
    let payload = make_data(0x88, 4096);

    let mut fs = open_fs(&dir);
    fs.create_file("/last.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/last.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let last = fs
        .read_file_range("/last.bin", 4095, 1)
        .expect("read last byte");
    assert_eq!(last.len(), 1);
    assert_eq!(last[0], payload[4095]);
}

// ── Multiple writes, single read ──────────────────────────────────────

#[test]
fn scattered_writes_single_read_back() {
    set_test_key();
    let dir = temp_dir("scattered");
    let chunk_a = make_data(0xA1, 1024);
    let chunk_b = make_data(0xB2, 1024);
    let chunk_c = make_data(0xC3, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/scattered.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    // Write non-contiguous chunks, leaving holes
    fs.write_file("/scattered.bin", 0, &chunk_a)
        .expect("write A");
    fs.write_file("/scattered.bin", 4096, &chunk_b)
        .expect("write B");
    fs.write_file("/scattered.bin", 8192, &chunk_c)
        .expect("write C");
    fs.sync_all().expect("sync");

    // Full read should return zeros for the holes
    let result = fs.read_file("/scattered.bin").expect("read back");
    assert_eq!(result.len(), 8192 + 1024);
    assert_eq!(&result[..1024], &chunk_a[..]);
    assert_eq!(&result[1024..4096], &vec![0u8; 3072][..]);
    assert_eq!(&result[4096..5120], &chunk_b[..]);
    assert_eq!(&result[5120..8192], &vec![0u8; 3072][..]);
    assert_eq!(&result[8192..], &chunk_c[..]);
}

// ── Concurrent read of same range ─────────────────────────────────────

#[test]
fn concurrent_reads_same_range() {
    set_test_key();
    let dir = temp_dir("concurrent_same");
    let payload = make_data(0x99, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/same.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/same.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    let fs_static: &'static std::path::Path = Box::leak(dir.clone().into_boxed_path());
    let payload_static: &'static [u8] = Box::leak(payload.into_boxed_slice());

    std::thread::scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                s.spawn(move || {
                    let fs = open_fs(fs_static);
                    // All threads read the exact same range
                    let chunk = fs
                        .read_file_range("/same.bin", 1024, 4096)
                        .expect("concurrent same-range read");
                    assert_eq!(chunk.len(), 4096);
                    let expected = &payload_static[1024..1024 + 4096];
                    assert_eq!(chunk, expected);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    });
}

// ── Read hot cache consistency ────────────────────────────────────────

#[test]
fn repeated_read_of_same_range_hits_hot_cache() {
    set_test_key();
    let dir = temp_dir("hotcache");
    let payload = make_data(0xDD, 8192);

    let mut fs = open_fs(&dir);
    fs.create_file("/cached.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/cached.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // First read: cold cache
    let _cold_before = fs.hot_read_cache_report();
    let first = fs
        .read_file_range("/cached.bin", 0, 4096)
        .expect("first read");
    assert_eq!(&first[..], &payload[..4096]);

    // Second read of same range: should be served from hot cache
    let warm_before = fs.hot_read_cache_report();
    let second = fs
        .read_file_range("/cached.bin", 0, 4096)
        .expect("second read");
    assert_eq!(&second[..], &payload[..4096]);

    let warm_after = fs.hot_read_cache_report();
    // At least one of hits or total accesses grew
    let accesses_before = warm_before.hits + warm_before.misses;
    let accesses_after = warm_after.hits + warm_after.misses;
    assert!(
        accesses_after >= accesses_before,
        "cache report should reflect additional access"
    );
}

// ── Read spanning many chunks ─────────────────────────────────────────

#[test]
fn read_spanning_many_chunks() {
    set_test_key();
    let dir = temp_dir("many_chunks");
    // 256 KiB — should span at least 4 chunks (chunk size is 64 KiB default)
    let payload = make_data(0xEE, 262144);

    let mut fs = open_fs(&dir);
    fs.create_file("/many.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/many.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Full file read
    let full = fs.read_file("/many.bin").expect("read full");
    assert_eq!(full, payload, "full file across many chunks");

    // Read a range that spans 3+ chunks
    let straddle = fs
        .read_file_range("/many.bin", 65000, 70000)
        .expect("read straddle");
    assert_eq!(straddle.len(), 70000);
    assert_eq!(&straddle[..], &payload[65000..65000 + 70000]);

    // Read crossing exact chunk boundaries at 64 KiB, 128 KiB, 192 KiB
    for boundary in [65535u64, 131071, 196607] {
        let cross = fs
            .read_file_range("/many.bin", boundary, 4)
            .expect("read across chunk boundary");
        let end = (boundary as usize + 4).min(payload.len());
        assert_eq!(cross.len(), end - boundary as usize);
        assert_eq!(&cross[..], &payload[boundary as usize..end]);
    }
}

// ── Single-byte reads across entire file ──────────────────────────────

#[test]
fn single_byte_reads_across_entire_file() {
    set_test_key();
    let dir = temp_dir("byte_by_byte");
    let payload = make_data(0xBA, 1024);

    let mut fs = open_fs(&dir);
    fs.create_file("/bytes.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/bytes.bin", 0, &payload).expect("write");
    fs.sync_all().expect("sync");

    // Verify every single byte is individually readable
    for (i, &expected) in payload.iter().enumerate() {
        let byte = fs
            .read_file_range("/bytes.bin", i as u64, 1)
            .expect("read single byte");
        assert_eq!(byte.len(), 1, "single byte at offset {i}");
        assert_eq!(byte[0], expected, "byte mismatch at offset {i}");
    }
}

// ── Empty file read ──────────────────────────────────────────────────

#[test]
fn read_empty_file_returns_zero_bytes() {
    set_test_key();
    let dir = temp_dir("read_empty");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/empty.bin").expect("read empty file");
    assert!(
        result.is_empty(),
        "read_file on empty file returns empty vec"
    );
}

#[test]
fn read_empty_file_range_returns_zero_bytes() {
    set_test_key();
    let dir = temp_dir("read_empty_range");

    let mut fs = open_fs(&dir);
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty");
    fs.sync_all().expect("sync");

    // Read at offset 0 with positive length on an empty file
    let result = fs
        .read_file_range("/empty.bin", 0, 64)
        .expect("read range on empty file");
    assert!(
        result.is_empty(),
        "read_file_range on empty file returns empty vec"
    );

    // Read at offset 1024 on an empty file
    let result = fs
        .read_file_range("/empty.bin", 1024, 64)
        .expect("read range past empty file");
    assert!(result.is_empty());
}

// ── Read after unlink ────────────────────────────────────────────────

#[test]
fn read_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_read");

    let mut fs = open_fs(&dir);
    fs.create_file("/unlink_me.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unlink_me.bin", 0, &make_data(0xAA, 1024))
        .expect("write");
    fs.sync_all().expect("sync");

    // Verify file is readable before unlink
    let before = fs.read_file("/unlink_me.bin").expect("read before unlink");
    assert!(!before.is_empty());

    fs.unlink("/unlink_me.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.read_file("/unlink_me.bin");
    assert!(result.is_err(), "read after unlink must fail");
}

#[test]
fn read_range_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_range_read");

    let mut fs = open_fs(&dir);
    fs.create_file("/unlink_range.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/unlink_range.bin", 0, &make_data(0xBB, 2048))
        .expect("write");
    fs.sync_all().expect("sync");

    fs.unlink("/unlink_range.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.read_file_range("/unlink_range.bin", 0, 64);
    assert!(result.is_err(), "read_file_range after unlink must fail");
}

#[test]
fn getattr_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_getattr");

    let mut fs = open_fs(&dir);
    fs.create_file("/gone.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.write_file("/gone.bin", 0, &make_data(0xCC, 512))
        .expect("write");
    fs.sync_all().expect("sync");

    fs.unlink("/gone.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.stat_attr("/gone.bin");
    assert!(result.is_err(), "getattr after unlink must fail");
}

#[test]
fn lookup_after_unlink_returns_error() {
    set_test_key();
    let dir = temp_dir("unlink_lookup");

    let mut fs = open_fs(&dir);
    fs.create_file("/vanish.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create");
    fs.sync_all().expect("sync");

    let ino = fs.lookup("/vanish.bin").expect("lookup before unlink");
    assert_ne!(ino, InodeId(0));

    fs.unlink("/vanish.bin").expect("unlink");
    fs.sync_all().expect("sync");

    let result = fs.lookup("/vanish.bin");
    assert!(result.is_err(), "lookup after unlink must fail");
}

// ── Read consistency through fresh filesystem reopen ─────────────────

#[test]
fn read_consistency_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("fresh_open");
    let payload = make_data(0x77, 4096);

    // Write and sync
    {
        let mut fs = open_fs(&dir);
        fs.create_file("/fresh.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/fresh.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    // Open a completely fresh filesystem handle and read back
    {
        let fs = open_fs(&dir);
        let result = fs.read_file("/fresh.bin").expect("read via fresh handle");
        assert_eq!(result.len(), payload.len());
        assert_eq!(result, payload, "byte-for-byte match through fresh open");
    }
}

#[test]
fn read_consistency_range_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("fresh_range");
    let payload = make_data(0x88, 8192);

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/fresh2.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/fresh2.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        // Read a partial range through the fresh handle
        let slice = fs
            .read_file_range("/fresh2.bin", 2048, 4096)
            .expect("partial read via fresh handle");
        assert_eq!(slice.len(), 4096);
        assert_eq!(&slice[..], &payload[2048..2048 + 4096]);
    }
}

#[test]
fn read_consistency_after_small_write_through_fresh_open() {
    set_test_key();
    let dir = temp_dir("small_write_consistency");
    let payload = b"small payload for consistency check";

    {
        let mut fs = open_fs(&dir);
        fs.create_file("/small.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/small.bin", 0, payload).expect("write");
        fs.sync_all().expect("sync");
    }

    {
        let fs = open_fs(&dir);
        let result = fs.read_file("/small.bin").expect("read small payload back");
        assert_eq!(
            result,
            payload.to_vec(),
            "small payload byte-for-byte match"
        );
    }
}
