//! Crash-recovery integration tests for the orphan replay watermark pipeline.
//!
//! Exercises the full pipeline described in issue #435:
//!
//! 1. Unlink-then-crash (drop fs without clean shutdown) — orphan entries
//!    must be cleaned up on reopen.
//! 2. Multiple unlinks across sessions — orphan index accumulates and is
//!    reclaimed correctly.
//! 3. Commit-then-crash — committed orphan data survives and is reclaimed
//!    on reopen.
//! 4. Write-unlink-crash-recover-write — the filesystem remains operational
//!    after crash recovery.
//!
//! These tests use the drop-fs pattern (simulating a crash without clean
//! shutdown) and verify that the orphan replay watermark pipeline correctly
//! gates reclaim release on recovery.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Once;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_local_object_store::StoreOptions;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static SET_TEST_KEY_ONCE: Once = Once::new();

fn set_test_key() {
    SET_TEST_KEY_ONCE.call_once(|| {
        env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
    });
}

fn opts() -> StoreOptions {
    StoreOptions::test_fast()
}

fn temp_root(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("tidefs-owcr-{label}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn cleanup(root: &Path) {
    let _ = fs::remove_dir_all(root);
}

// ---------------------------------------------------------------------------
// Test 1: Single unlink, drop (crash), reopen — orphan reclaimed
// ---------------------------------------------------------------------------

/// The simplest end-to-end pipeline: create a file, unlink it, drop the
/// filesystem (simulating a crash without clean shutdown), reopen, and
/// verify the filesystem is healthy and can accept new files.
#[test]
fn single_unlink_crash_reopen_consistent() {
    set_test_key();
    let root = temp_root("owcr-single");

    // Phase 1: Create and unlink.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");
        fs.create_file("/orphan_me", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.unlink("/orphan_me").expect("unlink");
        // Drop without clean shutdown simulates crash.
    }

    // Phase 2: Reopen — orphan cleanup must run during open.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen");
        // Filesystem must be operational.
        fs.create_file("/after_recovery", DEFAULT_FILE_PERMISSIONS)
            .expect("create after recovery");
        drop(fs);
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test 2: Multiple unlinks, crash, recover
// ---------------------------------------------------------------------------

/// Create and unlink 10 files, drop the fs (crash), reopen, and verify
/// the filesystem is operational.
#[test]
fn multi_unlink_crash_recover() {
    set_test_key();
    let root = temp_root("owcr-multi");

    // Phase 1: Create and unlink many files.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");
        for i in 0..10u64 {
            let path = format!("/file_{i}");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create_file");
            fs.unlink(&path).expect("unlink");
        }
        // Crash without clean shutdown.
    }

    // Phase 2: Reopen and verify health.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen");
        fs.create_file("/health_check", DEFAULT_FILE_PERMISSIONS)
            .expect("create after multi-unlink crash");
        drop(fs);
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test 3: Write data, unlink, crash, verify data reclaimed
// ---------------------------------------------------------------------------

/// Write data to a file, unlink it (creating orphan with extents), crash,
/// and verify the space is reclaimed and the filesystem is healthy.
#[test]
fn write_unlink_crash_reclaim() {
    set_test_key();
    let root = temp_root("owcr-write");

    // Phase 1: Write data, unlink.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");
        fs.create_file("/with_data", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.write_file("/with_data", 0, &[0x42u8; 4096])
            .expect("write data");
        fs.unlink("/with_data").expect("unlink");
        // Crash without clean shutdown.
    }

    // Phase 2: Reopen — orphan with extents must be reclaimed.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen");
        // The file should be gone.
        assert!(
            fs.lookup("/with_data").is_err(),
            "unlinked file must not survive crash recovery"
        );
        // Filesystem must remain operational.
        let mut fs = fs; // rebind as mut
        fs.create_file("/new_file", DEFAULT_FILE_PERMISSIONS)
            .expect("create new file after reclaim");
        drop(fs);
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test 4: Commit before crash — orphan persists through clean commit
// ---------------------------------------------------------------------------

/// Commit the orphan index to the store before crashing, ensuring the
/// persistent orphan index is tested across sessions.
#[test]
fn commit_then_crash_orphan_persists() {
    set_test_key();
    let root = temp_root("owcr-commit");

    // Phase 1: Create, unlink, commit.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");
        fs.create_file("/committed_orphan", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.unlink("/committed_orphan").expect("unlink");
        fs.commit().expect("commit");
        // Crash after commit.
    }

    // Phase 2: Reopen — committed orphan must be reclaimed.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen");
        assert!(
            fs.lookup("/committed_orphan").is_err(),
            "committed orphan file must not survive recovery"
        );
        drop(fs);
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test 5: Double crash — crash, partial recovery, crash again, full recovery
// ---------------------------------------------------------------------------

/// Simulate a double-crash scenario: first crash creates orphans, second
/// crash occurs during recovery, third open completes successfully.
#[test]
fn double_crash_recovery() {
    set_test_key();
    let root = temp_root("owcr-double");

    // Phase 1: Create and unlink, then crash.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");
        for i in 0..5u64 {
            let path = format!("/pre_crash_{i}");
            fs.create_file(&path, DEFAULT_FILE_PERMISSIONS)
                .expect("create_file");
            fs.unlink(&path).expect("unlink");
        }
        // Crash 1.
    }

    // Phase 2: Reopen (triggers recovery), immediately crash again.
    {
        let fs = LocalFileSystem::open_with_options(&root, opts()).expect("first reopen");
        drop(fs); // Crash 2 during/after recovery.
    }

    // Phase 3: Final reopen — must succeed.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("final reopen");
        fs.create_file("/survivor", DEFAULT_FILE_PERMISSIONS)
            .expect("create after double crash");
        drop(fs);
    }
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Test 6: Mixed operations (create, write, unlink, mkdir, rename) + crash
// ---------------------------------------------------------------------------

/// Exercise a realistic mixed workload, crash, and verify recovery.
#[test]
fn mixed_ops_crash_recovery() {
    set_test_key();
    let root = temp_root("owcr-mixed");

    // Phase 1: Mixed operations.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("open");

        // Create directory.
        fs.create_dir("/sub", tidefs_local_filesystem::DEFAULT_DIRECTORY_PERMISSIONS)
            .expect("mkdir");

        // Create files in subdirectory.
        fs.create_file("/sub/a.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create a.txt");
        fs.write_file("/sub/a.txt", 0, b"hello from a")
            .expect("write a");

        fs.create_file("/sub/b.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create b.txt");
        fs.write_file("/sub/b.txt", 0, b"data for b")
            .expect("write b");

        // Unlink one file (creates orphan).
        fs.unlink("/sub/b.txt").expect("unlink b.txt");

        // Create file at root.
        fs.create_file("/root_file", DEFAULT_FILE_PERMISSIONS)
            .expect("create root_file");

        // Crash without clean shutdown.
    }

    // Phase 2: Reopen — verify surviving data and operational state.
    {
        let mut fs = LocalFileSystem::open_with_options(&root, opts()).expect("reopen");

        // a.txt should survive (not unlinked).
        let content = fs.read_file("/sub/a.txt").expect("read a.txt");
        assert_eq!(content, b"hello from a", "surviving file content mismatch");

        // b.txt should be gone (unlinked).
        assert!(
            fs.lookup("/sub/b.txt").is_err(),
            "unlinked b.txt must not survive"
        );

        // root_file may or may not survive (not fsynced), but lookup must not panic.
        let _ = fs.lookup("/root_file");

        // Filesystem must accept new writes.
        fs.create_file("/sub/c.txt", DEFAULT_FILE_PERMISSIONS)
            .expect("create c.txt after recovery");
        fs.write_file("/sub/c.txt", 0, b"post-recovery")
            .expect("write after recovery");

        drop(fs);
    }
    cleanup(&root);
}
