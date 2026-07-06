// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-path validation: basic readback, multi-chunk read, pread offset,
//! sparse-file read, read-beyond-EOF, short read, concurrent reads, and
//! cross-file isolation.
//!
//! Exercises the full adapter stack (FUSE decode -> ingress -> capacity
//! dispatch -> page cache / extent map -> reply encode) through a real
//! FUSE mount.  Tests fail closed with an explicit runtime-refusal receipt
//! when the daemon binary, /dev/fuse, or another mounted-runtime prerequisite
//! is unavailable.
//!
//! The entire module is `#[cfg(test)]` because it contains only tests
//! and test helpers -- no library surface.

#[cfg(test)]
use crate::mount_harness::MountHarness;

#[cfg(test)]
use std::os::unix::fs::FileExt;

// ── Helpers ────────────────────────────────────────────────────────────────

#[cfg(test)]
/// Create a mount harness for tests that claim mounted read-path behavior.
fn mount_for_read_validation() -> MountHarness {
    MountHarness::new_or_fail("fuse_read_validation mounted read-path test")
}

#[cfg(test)]
/// Build `count` bytes of reproducible pseudo-random data so tests
/// can verify byte-for-byte readback without relying on all-zeros
/// (which would mask corruption).
fn make_test_data(count: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(count);
    for i in 0..count {
        // Simple deterministic pattern that changes every byte.
        let b = ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 32) as u8;
        buf.push(b);
    }
    buf
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    // ═══════════════════════════════════════════════════════════════════
    // Basic readback
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn basic_readback_verify_byte_for_byte() {
        let h = mount_for_read_validation();

        let data = make_test_data(4096);
        h.create_file("basic.bin", &data).expect("create basic.bin");
        let got = h.read_file("basic.bin").expect("read basic.bin");
        assert_eq!(got, data, "readback must match written data byte-for-byte");
    }

    #[test]
    fn basic_readback_single_byte() {
        let h = mount_for_read_validation();

        h.create_file("one.bin", b"X").expect("create");
        let got = h.read_file("one.bin").expect("read");
        assert_eq!(got, b"X", "single-byte file readback");
    }

    #[test]
    fn basic_readback_empty_file() {
        let h = mount_for_read_validation();

        h.create_file("empty.bin", b"").expect("create");
        let got = h.read_file("empty.bin").expect("read");
        assert!(
            got.is_empty(),
            "empty file read must yield zero bytes, got {} bytes",
            got.len()
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Multi-chunk read
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn multichunk_128kib_read_full() {
        let h = mount_for_read_validation();

        let data = make_test_data(128 * 1024);
        h.create_file("big.bin", &data).expect("create");
        let got = h.read_file("big.bin").expect("read");
        assert_eq!(got, data, "128 KiB readback must be exact match");
    }

    #[test]
    fn multichunk_128kib_read_in_4kib_chunks() {
        let h = mount_for_read_validation();

        let data = make_test_data(128 * 1024);
        h.create_file("big.bin", &data).expect("create");

        let path = h.mount_path().join("big.bin");
        let file = File::open(&path).expect("open big.bin");

        let chunk_size = 4096usize;
        let mut offset = 0u64;
        let mut buf = vec![0u8; chunk_size];
        let mut collected = Vec::with_capacity(data.len());

        while (offset as usize) < data.len() {
            let remaining = data.len() - offset as usize;
            let to_read = chunk_size.min(remaining);
            let n = file.read_at(&mut buf[..to_read], offset).expect("read_at");
            assert_eq!(n, to_read, "short read at offset {offset}");
            collected.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }

        assert_eq!(collected, data, "chunked readback must match written data");
    }

    #[test]
    fn multichunk_unaligned_read_512b() {
        let h = mount_for_read_validation();

        // Start with an unaligned offset and read small chunks.
        let data = make_test_data(16384);
        h.create_file("unaligned.bin", &data).expect("create");

        let path = h.mount_path().join("unaligned.bin");
        let file = File::open(&path).expect("open");

        let mut offset = 7u64;
        let mut buf = vec![0u8; 512];
        let mut collected = Vec::new();

        while (offset as usize) < data.len() {
            let n = file.read_at(&mut buf, offset).expect("read_at");
            if n == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..n]);
            offset += n as u64;
        }

        let expected = &data[7..];
        assert_eq!(
            collected, expected,
            "unaligned 512 B chunked read must match tail of data"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // pread offset
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn pread_offset_start() {
        let h = mount_for_read_validation();

        let data = make_test_data(8192);
        h.create_file("pread.bin", &data).expect("create");

        let path = h.mount_path().join("pread.bin");
        let file = File::open(&path).expect("open");

        let mut buf = vec![0u8; 1024];
        let n = file.read_at(&mut buf, 0).expect("read_at offset 0");
        assert_eq!(&buf[..n], &data[..n], "pread offset 0");
    }

    #[test]
    fn pread_offset_middle() {
        let h = mount_for_read_validation();

        let data = make_test_data(8192);
        h.create_file("pread.bin", &data).expect("create");

        let path = h.mount_path().join("pread.bin");
        let file = File::open(&path).expect("open");

        let start: u64 = 500;
        let len = 1500;
        let mut buf = vec![0u8; len];
        let n = file.read_at(&mut buf, start).expect("read_at middle");
        let expected = &data[start as usize..(start as usize + n)];
        assert_eq!(&buf[..n], expected, "pread offset {start}");
        assert_eq!(n, len, "should read full requested length");
    }

    #[test]
    fn pread_offset_last_byte() {
        let h = mount_for_read_validation();

        let data = make_test_data(4096);
        h.create_file("last.bin", &data).expect("create");

        let path = h.mount_path().join("last.bin");
        let file = File::open(&path).expect("open");

        let mut buf = [0u8; 1];
        let last_off = (data.len() - 1) as u64;
        let n = file.read_at(&mut buf, last_off).expect("read_at last byte");
        assert_eq!(n, 1, "should read exactly one byte at last offset");
        assert_eq!(buf[0], data[last_off as usize], "last byte must match");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Sparse file read
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn sparse_file_hole_reads_as_zero() {
        let h = mount_for_read_validation();

        let path = h.mount_path().join("sparse.bin");

        // Create by writing at offset far beyond file start to create a hole.
        {
            let file = File::create(&path).expect("create sparse.bin");
            // Write a single byte at offset 4096 (hole from 0..4095).
            file.write_at(b"X", 4096).expect("write_at 4096");
        }

        // Read the hole region (offset 0..4095).
        {
            let file = File::open(&path).expect("open sparse.bin");
            let mut buf = vec![1u8; 4096]; // fill with non-zero to detect zero-fill
            let n = file.read_at(&mut buf, 0).expect("read_at hole");
            // Should read 4096 zero bytes then EOF at 4097 (or 4096 if hole stops).
            // The kernel should zero-fill the hole region.
            assert!(n >= 4096, "should read at least hole region, got {n}");

            // Hole bytes must be zero.
            let hole = &buf[..4096];
            assert!(
                hole.iter().all(|&b| b == 0),
                "hole region must be zero-filled, found non-zero byte"
            );
        }
    }

    #[test]
    fn sparse_file_data_after_hole_is_preserved() {
        let h = mount_for_read_validation();

        let path = h.mount_path().join("sparse2.bin");

        {
            let file = File::create(&path).expect("create");
            let marker = b"DATA_AFTER_HOLE";
            file.write_at(marker, 8192).expect("write_at 8192");
        }

        {
            let file = File::open(&path).expect("open");
            let mut buf = vec![0u8; 15];
            let n = file.read_at(&mut buf, 8192).expect("read_at 8192");
            assert_eq!(n, 15, "should read 15 bytes at offset 8192");
            assert_eq!(
                &buf[..n],
                b"DATA_AFTER_HOLE",
                "data beyond hole must be intact"
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Read beyond EOF
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn read_beyond_eof_returns_zero_bytes() {
        let h = mount_for_read_validation();

        let data = b"hello";
        h.create_file("short.bin", data).expect("create");

        let path = h.mount_path().join("short.bin");
        let file = File::open(&path).expect("open");

        let mut buf = [0u8; 64];
        let n = file
            .read_at(&mut buf, data.len() as u64)
            .expect("read_at beyond EOF");
        assert_eq!(n, 0, "read beyond EOF must return zero bytes");
    }

    #[test]
    fn read_partially_beyond_eof_short_read() {
        let h = mount_for_read_validation();

        let data = b"abcdefghij"; // 10 bytes
        h.create_file("ten.bin", data).expect("create");

        let path = h.mount_path().join("ten.bin");
        let file = File::open(&path).expect("open");

        // Start at offset 7, request 10 bytes — only 3 remain.
        let mut buf = [0u8; 10];
        let n = file.read_at(&mut buf, 7).expect("read_at partial");
        assert_eq!(n, 3, "short read should return only remaining bytes");
        assert_eq!(&buf[..n], &data[7..], "short read content must match tail");
    }

    #[test]
    fn read_at_exact_eof_returns_zero() {
        let h = mount_for_read_validation();

        h.create_file("exact.bin", b"1234").expect("create");

        let path = h.mount_path().join("exact.bin");
        let file = File::open(&path).expect("open");

        let mut buf = [0u8; 4];
        let n = file.read_at(&mut buf, 4).expect("read_at exact EOF");
        assert_eq!(n, 0, "read at exact EOF offset must return zero bytes");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Concurrent reads
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn concurrent_reads_same_file_consistent() {
        let h = mount_for_read_validation();

        let data = make_test_data(65536);
        h.create_file("shared.bin", &data).expect("create");

        let path = h.mount_path().join("shared.bin");

        let mut handles = Vec::new();
        for _ in 0..4 {
            let p = path.clone();
            let expected = data.clone();
            handles.push(std::thread::spawn(move || {
                let file = File::open(&p).expect("open in thread");
                let mut buf = vec![0u8; expected.len()];
                let n = file.read_at(&mut buf, 0).expect("read_at in thread");
                assert_eq!(n, expected.len(), "thread read must get full file");
                assert_eq!(&buf[..n], &expected[..], "thread read content must match");
            }));
        }

        for handle in handles {
            handle.join().expect("thread join");
        }
    }

    #[test]
    fn concurrent_reads_different_offsets() {
        let h = mount_for_read_validation();

        let data = make_test_data(16384);
        h.create_file("multi.bin", &data).expect("create");

        let path = h.mount_path().join("multi.bin");

        // Thread 1 reads first half; thread 2 reads second half.
        let p1 = path.clone();
        let d1 = data.clone();
        let t1 = std::thread::spawn(move || {
            let file = File::open(&p1).expect("open");
            let mut buf = vec![0u8; 8192];
            let n = file.read_at(&mut buf, 0).expect("read_at first half");
            assert_eq!(n, 8192);
            assert_eq!(&buf[..n], &d1[..8192]);
        });

        let p2 = path.clone();
        let d2 = data.clone();
        let t2 = std::thread::spawn(move || {
            let file = File::open(&p2).expect("open");
            let mut buf = vec![0u8; 8192];
            let n = file.read_at(&mut buf, 8192).expect("read_at second half");
            assert_eq!(n, 8192);
            assert_eq!(&buf[..n], &d2[8192..]);
        });

        t1.join().expect("t1 join");
        t2.join().expect("t2 join");
    }

    // ═══════════════════════════════════════════════════════════════════
    // Cross-file isolation
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn read_after_unlink_other_file_preserves_data() {
        let h = mount_for_read_validation();

        let data_a = make_test_data(2048);
        let data_b = make_test_data(1024);

        h.create_file("a.bin", &data_a).expect("create a.bin");
        h.create_file("b.bin", &data_b).expect("create b.bin");

        // Unlink b.bin.
        h.remove_file("b.bin").expect("remove b.bin");
        assert!(!h.exists("b.bin"), "b.bin must not exist after unlink");

        // Read a.bin — must be intact.
        let got = h.read_file("a.bin").expect("read a.bin after unlink b");
        assert_eq!(
            got, data_a,
            "file a.bin must be intact after unlinking unrelated file b.bin"
        );
    }

    #[test]
    fn read_unchanged_after_write_to_other_file() {
        let h = mount_for_read_validation();

        let data_a = make_test_data(1024);
        h.create_file("a.bin", &data_a).expect("create a.bin");

        // Read once to verify.
        let first = h.read_file("a.bin").expect("first read a.bin");
        assert_eq!(first, data_a);

        // Write to unrelated file.
        let data_c = make_test_data(4096);
        h.create_file("c.bin", &data_c).expect("create c.bin");

        // Read a.bin again — must be unchanged.
        let second = h.read_file("a.bin").expect("second read a.bin");
        assert_eq!(
            second, data_a,
            "file a.bin must be unchanged after writing unrelated file c.bin"
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // Sparse file + dedup interaction
    // ═══════════════════════════════════════════════════════════════════

    /// Write duplicate content through FUSE into a sparse layout
    /// (data + hole + data).  The inline dedup path should redirect
    /// duplicate chunks to the canonical object without affecting the
    /// hole region or the surrounding data blocks.
    ///
    /// This is the Tier 3 mounted-FUSE validation that dedup does not
    /// collapse holes or corrupt sparse reads.
    #[test]
    fn sparse_file_with_duplicate_data_preserves_holes_and_data() {
        let h = MountHarness::builder()
            .enable_dedup()
            .build()
            .unwrap_or_else(|e| {
                panic!(
                    "{}",
                    MountHarness::runtime_refusal_message(
                        "fuse_read_validation dedup sparse read test",
                        e
                    )
                )
            });

        let payload = make_test_data(4096);
        let different = make_test_data(8192);
        let different_data = &different[..4096];

        let path = h.mount_path().join("sparse_dup.bin");

        // Phase 1: write canonical file so dedup index has an entry.
        h.create_file("canonical.bin", &payload)
            .expect("create canonical.bin");

        // Phase 2: create a sparse file through FUSE.
        // Layout: data(0..4096) hole(4096..8192) data(8192..12288)
        // The first data block duplicates the canonical file content,
        // so the inline dedup path must redirect it.
        {
            use std::os::unix::fs::FileExt;
            let file = File::create(&path).expect("create sparse_dup.bin");
            file.write_at(&payload, 0)
                .expect("write_at 0 (duplicate of canonical)");
            // Hole from 4096..8192 is implicit (nothing written there).
            file.write_at(different_data, 8192).expect("write_at 8192");
        }

        // Phase 3: verify canonical file still reads correctly.
        let canon_read = h.read_file("canonical.bin").expect("read canonical.bin");
        assert_eq!(
            canon_read, payload,
            "canonical file must read back correctly after dedup redirect"
        );

        // Phase 4: read the sparse file's first data block (offset 0).
        {
            use std::os::unix::fs::FileExt;
            let file = File::open(&path).expect("open sparse_dup.bin");
            let mut buf = vec![0u8; 4096];
            let n = file.read_at(&mut buf, 0).expect("read_at 0");
            assert!(
                n >= 4096,
                "must read at least 4096 bytes from offset 0, got {n}"
            );
            assert_eq!(
                &buf[..4096],
                &payload[..],
                "data at offset 0 must match payload (dedup redirect preserved)"
            );
        }

        // Phase 5: read the hole region (offset 4096..8192).
        {
            use std::os::unix::fs::FileExt;
            let file = File::open(&path).expect("open sparse_dup.bin for hole");
            let mut buf = vec![1u8; 4096];
            let n = file.read_at(&mut buf, 4096).expect("read_at 4096 (hole)");
            assert!(
                n >= 4096,
                "must read at least 4096 bytes from hole, got {n}"
            );
            assert!(
                buf.iter().all(|&b| b == 0),
                "hole region must be all zeros (dedup must not corrupt hole)"
            );
        }

        // Phase 6: read third data block (offset 8192).
        {
            use std::os::unix::fs::FileExt;
            let file = File::open(&path).expect("open sparse_dup.bin for tail");
            let mut buf = vec![0u8; 4096];
            let n = file.read_at(&mut buf, 8192).expect("read_at 8192");
            assert_eq!(n, 4096, "must read exactly 4096 bytes from offset 8192");
            assert_eq!(
                &buf[..n],
                different_data,
                "data at offset 8192 must match written data"
            );
        }

        // Phase 7: verify file size.
        {
            let md = std::fs::metadata(&path).expect("stat sparse_dup.bin");
            assert_eq!(
                md.len(),
                12288,
                "sparse file size must be 12288 (8192 + 4096)"
            );
        }
    }
}
