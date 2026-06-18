// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Crash-consistency unit tests for the local-filesystem layer.
//!
//! Exercises data-or-nothing semantics: write some data with fsync,
//! write more without fsync, drop the filesystem (simulating crash),
//! reopen, and verify fsynced data is intact while un-synced data
//! may be lost but must not corrupt the filesystem.
//!
//! These complement the heavy crash-injection tests in
//! crash_injection_tests.rs (which use fork+arm for fine-grained hooks)
//! with lighter unit-level reopen-and-verify tests.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

// ── Helpers ───────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-cc-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
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

// ── Fsynced data survives crash ───────────────────────────────────────

#[test]
fn fsynced_data_survives_reopen() {
    set_test_key();
    let dir = temp_dir("fsync_survives");
    let payload = make_data(0x42, 8192);

    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/safe.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/safe.bin", 0, &payload).expect("write");
        fs.sync_all().expect("sync");
    } // filesystem dropped (simulates clean close)

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");
        let recovered = fs.read_file("/safe.bin").expect("read after reopen");
        assert_eq!(recovered, payload, "fsynced data intact after reopen");
        let attr = fs.stat_attr("/safe.bin").expect("stat");
        assert_eq!(attr.posix.size, 8192);
    }
}

// ── Un-fsynced data may be lost but filesystem stays consistent ───────

#[test]
fn unfsynced_data_reopen_filesystem_consistent() {
    set_test_key();
    let dir = temp_dir("nofsync_reopen");

    // First session: write fsynced data
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/stable.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        let stable = make_data(0x11, 4096);
        fs.write_file("/stable.bin", 0, &stable)
            .expect("write stable");
        fs.sync_all().expect("sync stable");

        // Write more without fsync
        let _unstable = make_data(0x22, 2048);
        fs.write_file("/stable.bin", 4096, &make_data(0x22, 2048))
            .ok();
        // No fsync — crash
    }

    // Reopen: filesystem must be healthy
    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");
        // The fsynced data must be intact
        let recovered = fs.read_file("/stable.bin").expect("read after reopen");
        // The first 4096 bytes (fsynced) must be present
        assert!(recovered.len() >= 4096, "fsynced bytes preserved");
        assert_eq!(
            &recovered[..4096],
            &make_data(0x11, 4096)[..],
            "fsynced prefix intact"
        );

        // Beyond fsync, data-or-nothing: either old state or new state,
        // but filesystem must be internally consistent (no panics, no
        // checksum failures).
        let _ = fs.stat_attr("/stable.bin").expect("stat works");
    }
}

// ── Crash mid-write on newly created file ─────────────────────────────

#[test]
fn crash_mid_write_new_file_reopen_consistent() {
    set_test_key();
    let dir = temp_dir("crash_new_file");

    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/doomed.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/doomed.bin", 0, &make_data(0xAA, 12288))
            .ok();
        // No fsync — crash
    }

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");
        // File may exist or not, but lookup must not panic
        match fs.lookup("/doomed.bin") {
            Ok(_ino) => {
                // If it exists, reading must succeed or fail cleanly
                let _ = fs.read_file("/doomed.bin");
            }
            Err(_) => {
                // File gone is also acceptable (data-or-nothing)
            }
        }
    }
}

// ── Crash after unlink, before sync ───────────────────────────────────

#[test]
fn crash_after_unlink_reopen_consistent() {
    set_test_key();
    let dir = temp_dir("crash_unlink");

    // Create and fsync a file
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/present.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/present.bin", 0, &make_data(0xBB, 1024))
            .expect("write");
        fs.sync_all().expect("sync");
    }

    // Reopen, unlink without fsync, crash
    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen");
        fs.unlink("/present.bin").ok();
        // No fsync — crash
    }

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen again");
        // Either the file still exists (unlink lost) or it's gone.
        // Either way, the filesystem must be healthy.
        let _ = fs.lookup("/present.bin");
        let _ = fs.stat_attr("/present.bin");
    }
}

// ── Multiple files, partial fsync ─────────────────────────────────────

#[test]
fn multiple_files_partial_fsync_reopen_consistent() {
    set_test_key();
    let dir = temp_dir("multi_partial");

    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");

        // File A: created and fsynced
        fs.create_file("/a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create a");
        fs.write_file("/a.bin", 0, &make_data(0xA1, 2048))
            .expect("write a");
        fs.sync_all().expect("sync a");

        // File B: created but NOT fsynced
        fs.create_file("/b.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create b");
        fs.write_file("/b.bin", 0, &make_data(0xB2, 2048)).ok();
        // No fsync — crash
    }

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");

        // File A must be intact
        let a = fs.read_file("/a.bin").expect("read a after reopen");
        assert_eq!(a, make_data(0xA1, 2048), "fsynced file A intact");

        // File B may exist or not
        match fs.lookup("/b.bin") {
            Ok(_) => {
                let b = fs.read_file("/b.bin").expect("read b if exists");
                // If it exists, its content could be any prefix
                assert!(b.len() <= 2048);
            }
            Err(_) => { /* acceptable: data-or-nothing */ }
        }
    }
}

// ── Overwrite survives reopen (eager persistence) ─────────────────────

#[test]
fn overwrite_survives_reopen_even_without_explicit_fsync() {
    set_test_key();
    let dir = temp_dir("overwrite_reopen");
    let original = make_data(0x55, 8192);

    // Write and fsync original data
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_file("/overlay.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create");
        fs.write_file("/overlay.bin", 0, &original)
            .expect("write original");
        fs.sync_all().expect("sync original");
    }

    // Reopen, overwrite part, drop without explicit sync
    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen");
        let new_data = make_data(0x99, 4096);
        fs.write_file("/overlay.bin", 0, &new_data)
            .expect("overwrite");
        // No explicit fsync — filesystem may eagerly persist
    }

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen again");
        let recovered = fs.read_file("/overlay.bin").expect("read after reopen");
        // The overwrite prefix should be the new data (eager persistence)
        assert_eq!(
            &recovered[..4096],
            &make_data(0x99, 4096)[..],
            "overwrite prefix persisted"
        );
        // The suffix beyond the overwrite should be original
        assert_eq!(
            &recovered[4096..],
            &original[4096..],
            "un-overwritten suffix preserved"
        );
        assert_eq!(recovered.len(), 8192);
    }
}

// ── crash after create dir with files ─────────────────────────────────

#[test]
fn crash_after_create_dir_with_files_reopen_consistent() {
    set_test_key();
    let dir = temp_dir("crash_dir");

    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.create_dir("/data", 0o755).expect("create dir");
        fs.create_file("/data/f1.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create f1");
        fs.write_file("/data/f1.bin", 0, &make_data(0xCC, 512))
            .expect("write f1");
        fs.sync_all().expect("sync f1");

        // Create f2 without fsync
        fs.create_file("/data/f2.bin", DEFAULT_FILE_PERMISSIONS)
            .ok();
        // Crash
    }

    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");
        // Directory and fsynced file must exist
        let entries = fs.list_dir("/data").expect("list /data");
        let names: Vec<_> = entries.iter().map(|e| &e.name).collect();
        assert!(
            names.iter().any(|n| n == &b"f1.bin"),
            "fsynced file f1.bin present"
        );
        // f2 may or may not exist
        let _ = fs.lookup("/data/f2.bin");
    }
}
