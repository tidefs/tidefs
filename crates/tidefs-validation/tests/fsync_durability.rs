// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Local-filesystem fsync durability integration tests.
//!
//! Exercises the write → fsync → drop → reopen → read → verify durability
//! loop directly against [`tidefs_local_filesystem::LocalFileSystem`] and
//! [`tidefs_local_object_store`], without requiring a live FUSE mount or
//! daemon process.  This validates the internal plumbing needed for the
//! `fuse-fsync-durability` milestone at the storage layer.
//!
//! Every test name includes `write_durability` so the phase advancement
//! criteria filter `cargo test -p tidefs-validation -- write_durability`
//! picks them up automatically (when compiled with `--features
//! local-filesystem,object-store`).

#![cfg(feature = "fuse")]

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_filesystem::{LocalFileSystem, RootAuthenticationKey, DEFAULT_FILE_PERMISSIONS};
use tidefs_local_object_store::StoreOptions;

// ── helpers ──────────────────────────────────────────────────────────────

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-fsync-dur-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &Path) {
    let _ = std::fs::remove_dir_all(root);
}

fn store_opts() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 16 * 1024,
        sync_on_write: false,
        background_scrub_interval_secs: 0,
        reclaim_enabled: true,
        ..StoreOptions::durable()
    }
}

fn auth_key() -> RootAuthenticationKey {
    RootAuthenticationKey::demo_key()
}

/// Deterministic incrementing byte sequence.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// Pseudo-random data seeded by `seed` for `len` bytes.
fn prng_data(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
    (0..len)
        .map(|_| {
            let b = (state >> 32) as u8;
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            b
        })
        .collect()
}

/// Open a filesystem on `root` with the standard test options and demo key.
fn open_fs(root: &Path) -> LocalFileSystem {
    LocalFileSystem::open_with_root_authentication_key(root, store_opts(), auth_key())
        .expect("open LocalFileSystem")
}

// ── single-file fsync durability ─────────────────────────────────────────

/// Write a small file, fsync, drop the filesystem, reopen, and verify
/// byte-for-byte match.  This is the foundational non-FUSE durability test.
#[test]
fn write_durability_fsync_reopen_small_file() {
    let root = temp_root("small-file");
    cleanup(&root);

    let data = b"TideFS fsync durability: data survives filesystem reopen.";

    {
        let mut fs = open_fs(&root);
        fs.create_file("/small.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file("/small.bin", data).expect("write data");
        fs.fsync_file("/small.bin").expect("fsync_file");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/small.bin").expect("read_file session 2");
        assert_eq!(
            read_back,
            data.as_slice(),
            "byte-for-byte mismatch after fsync + drop + reopen"
        );
    }

    cleanup(&root);
}

// ── sequenced multi-block file ───────────────────────────────────────────

/// Write 8 KiB of deterministic sequenced data, fsync, drop, reopen, verify.
#[test]
fn write_durability_fsync_reopen_8kib_sequenced() {
    let root = temp_root("8kib-seq");
    cleanup(&root);

    let data = seq_data(8192);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/seq.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file("/seq.bin", &data).expect("write data");
        fs.fsync_file("/seq.bin").expect("fsync_file");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/seq.bin").expect("read_file session 2");
        assert_eq!(read_back.len(), data.len(), "length mismatch after reopen");
        assert_eq!(
            read_back, data,
            "byte-for-byte mismatch after fsync + reopen (8 KiB)"
        );
    }

    cleanup(&root);
}

// ── pseudo-random data with verify helper ────────────────────────────────

/// Verify `got` matches `prng_data(seed, got.len())` byte-for-byte.
fn verify_prng(seed: u64, got: &[u8]) -> Result<(), String> {
    let expected = prng_data(seed, got.len());
    if got.len() != expected.len() {
        return Err(format!(
            "length mismatch: {} vs {}",
            got.len(),
            expected.len()
        ));
    }
    for (i, (a, b)) in got.iter().zip(expected.iter()).enumerate() {
        if a != b {
            return Err(format!(
                "byte mismatch at offset {i}: 0x{a:02x} vs 0x{b:02x}"
            ));
        }
    }
    Ok(())
}

/// Write 4 KiB of pseudo-random data, fsync, drop, reopen, verify.
#[test]
fn write_durability_fsync_reopen_4kib_prng() {
    let root = temp_root("4kib-prng");
    cleanup(&root);

    let seed: u64 = 0xcafe_babe_dead_beef;
    let data = prng_data(seed, 4096);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/prng.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file("/prng.bin", &data).expect("write data");
        fs.fsync_file("/prng.bin").expect("fsync_file");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/prng.bin").expect("read_file session 2");
        if let Err(e) = verify_prng(seed, &read_back) {
            panic!("prng verification failed after fsync + reopen: {e}");
        }
    }

    cleanup(&root);
}

// ── multi-file fsync durability ──────────────────────────────────────────

/// Write three files with distinct content, fsync each, drop, reopen,
/// verify all three byte-for-byte.
#[test]
fn write_durability_fsync_reopen_three_files() {
    let root = temp_root("three-files");
    cleanup(&root);

    let data_a = seq_data(512);
    let data_b = b"middle file with known text content\n".to_vec();
    let data_c = prng_data(0xdead_f00d, 2048);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create /a.bin");
        fs.create_file("/b.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create /b.txt");
        fs.create_file("/c.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create /c.bin");

        fs.replace_file("/a.bin", &data_a).expect("write /a.bin");
        fs.replace_file("/b.txt", &data_b).expect("write /b.txt");
        fs.replace_file("/c.bin", &data_c).expect("write /c.bin");

        fs.fsync_file("/a.bin").expect("fsync /a.bin");
        fs.fsync_file("/b.txt").expect("fsync /b.txt");
        fs.fsync_file("/c.bin").expect("fsync /c.bin");
    }

    {
        let fs = open_fs(&root);
        let ra = fs.read_file("/a.bin").expect("read /a.bin");
        let rb = fs.read_file("/b.txt").expect("read /b.txt");
        let rc = fs.read_file("/c.bin").expect("read /c.bin");

        assert_eq!(ra, data_a, "/a.bin mismatch after fsync+reopen");
        assert_eq!(rb, data_b, "/b.txt mismatch after fsync+reopen");
        assert_eq!(rc, data_c, "/c.bin mismatch after fsync+reopen");
    }

    cleanup(&root);
}

// ── fsync_all durability ─────────────────────────────────────────────────

/// Write two files, call `fsync_all()` instead of per-file fsync, drop,
/// reopen, verify both survived.
#[test]
fn write_durability_fsync_all_reopen() {
    let root = temp_root("fsync-all");
    cleanup(&root);

    let data_x = seq_data(1024);
    let data_y = prng_data(0xabcd, 256);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/x.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create /x.bin");
        fs.create_file("/y.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create /y.bin");
        fs.replace_file("/x.bin", &data_x).expect("write /x.bin");
        fs.replace_file("/y.bin", &data_y).expect("write /y.bin");
        fs.fsync_all().expect("fsync_all");
    }

    {
        let fs = open_fs(&root);
        let rx = fs.read_file("/x.bin").expect("read /x.bin");
        let ry = fs.read_file("/y.bin").expect("read /y.bin");
        assert_eq!(rx, data_x, "/x.bin mismatch after fsync_all+reopen");
        assert_eq!(ry, data_y, "/y.bin mismatch after fsync_all+reopen");
    }

    cleanup(&root);
}

// ── nested directory structure durability ────────────────────────────────

/// Create a nested directory, write a file inside, fsync, drop, reopen,
/// verify the directory exists and the file content matches.
#[test]
fn write_durability_fsync_reopen_nested_dir() {
    let root = temp_root("nested-dir");
    cleanup(&root);

    let data = b"deeply nested file content\n".to_vec();

    {
        let mut fs = open_fs(&root);
        fs.create_dir("/alpha", DEFAULT_FILE_PERMISSIONS)
            .expect("create /alpha");
        fs.create_dir("/alpha/beta", DEFAULT_FILE_PERMISSIONS)
            .expect("create /alpha/beta");
        fs.create_file("/alpha/beta/deep.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create deep file");
        fs.replace_file("/alpha/beta/deep.bin", &data)
            .expect("write deep file");
        fs.fsync_file("/alpha/beta/deep.bin")
            .expect("fsync deep file");
    }

    {
        let fs = open_fs(&root);

        let entries_alpha = fs.list_dir("/alpha").expect("list /alpha");
        let has_beta = entries_alpha.iter().any(|e| e.name == b"beta");
        assert!(has_beta, "/alpha should contain beta/ after reopen");

        let entries_beta = fs.list_dir("/alpha/beta").expect("list /alpha/beta");
        let has_deep = entries_beta.iter().any(|e| e.name == b"deep.bin");
        assert!(has_deep, "/alpha/beta should contain deep.bin after reopen");

        let read_back = fs
            .read_file("/alpha/beta/deep.bin")
            .expect("read deep file");
        assert_eq!(read_back, data, "deep file mismatch after fsync+reopen");
    }

    cleanup(&root);
}

// ── overwrite durability ─────────────────────────────────────────────────

/// Write initial content, fsync, overwrite with new content, fsync again,
/// drop, reopen, and verify the second (overwritten) content survived.
#[test]
fn write_durability_fsync_overwrite_reopen() {
    let root = temp_root("overwrite");
    cleanup(&root);

    let initial = b"original content\n";
    let overwrite = b"overwritten content that should survive\n";

    {
        let mut fs = open_fs(&root);
        fs.create_file("/over.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.replace_file("/over.bin", initial)
            .expect("write initial");
        fs.fsync_file("/over.bin").expect("fsync initial");

        fs.replace_file("/over.bin", overwrite).expect("overwrite");
        fs.fsync_file("/over.bin").expect("fsync overwrite");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/over.bin").expect("read session 2");
        assert_eq!(
            read_back,
            overwrite.as_slice(),
            "overwritten content should survive fsync+reopen; \
             got initial content instead"
        );
    }

    cleanup(&root);
}

// ── large-file multi-extent durability ───────────────────────────────────

/// Write 12 KiB of pseudo-random data (spanning multiple extents), fsync,
/// drop, reopen, verify byte-for-byte.
#[test]
fn write_durability_fsync_reopen_large_12kib() {
    let root = temp_root("large-256kib");
    cleanup(&root);

    let seed: u64 = 0x0123_4567_89ab_cdef;
    let data = prng_data(seed, 12 * 1024);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/large.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.replace_file("/large.bin", &data).expect("write 12 KiB");
        fs.fsync_file("/large.bin").expect("fsync");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/large.bin").expect("read session 2");
        if let Err(e) = verify_prng(seed, &read_back) {
            panic!("large file verification failed after fsync+reopen: {e}");
        }
    }

    cleanup(&root);
}

// ── empty file durability ────────────────────────────────────────────────

/// Create an empty file (no data), fsync, drop, reopen, verify it exists
/// and is empty.
#[test]
fn write_durability_fsync_reopen_empty_file() {
    let root = temp_root("empty-file");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create empty");
        fs.fsync_file("/empty.bin").expect("fsync empty");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/empty.bin").expect("read empty file");
        assert!(
            read_back.is_empty(),
            "empty file should remain empty after reopen"
        );
        let stat = fs.stat("/empty.bin").expect("stat empty file");
        assert_eq!(stat.size, 0, "empty file size should be 0 after reopen");
    }

    cleanup(&root);
}

// ── data-only fsync (fdatasync semantics) ────────────────────────────────

/// Write data, call `fsync_data_only_file`, drop, reopen, verify content
/// survived (fdatasync flushes data but may skip metadata timestamp sync).
#[test]
fn write_durability_fdatasync_reopen_4kib() {
    let root = temp_root("fdatasync");
    cleanup(&root);

    let data = seq_data(4096);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/fd.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.replace_file("/fd.bin", &data).expect("write");
        fs.fsync_data_only_file("/fd.bin").expect("fsync_data_only");
    }

    {
        let fs = open_fs(&root);
        let read_back = fs.read_file("/fd.bin").expect("read session 2");
        assert_eq!(
            read_back, data,
            "fdatasync: data mismatch after drop + reopen"
        );
    }

    cleanup(&root);
}
