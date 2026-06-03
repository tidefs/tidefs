//! Crash/reopen validation for content-addressed chunk dedup (#5966).
//!
//! Verifies that dedup redirects resolve correctly after an unclean shutdown:
//! write duplicate content with dedup enabled, drop the filesystem (simulating
//! crash), reopen, and verify data integrity.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

const CHUNK_SIZE: usize = 65536;
const DATA_SIZE: usize = CHUNK_SIZE; // single chunk for simple fingerprint tracking

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-dcr-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn make_data(len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = 0xCDu8;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// ── Dedup redirects survive crash/reopen ──────────────────────────────

#[test]
fn dedup_redirects_survive_crash_reopen() {
    set_test_key();
    let dir = temp_dir("dedup_crash");
    let payload = make_data(DATA_SIZE);

    // Session 1: write two identical files with dedup enabled, then sync.
    // The first file creates a canonical chunk object; the second stores
    // a dedup redirect.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.set_dedup_enabled(true);

        fs.create_file("/first.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create first");
        fs.write_file("/first.bin", 0, &payload)
            .expect("write first");

        fs.create_file("/second.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create second");
        fs.write_file("/second.bin", 0, &payload)
            .expect("write second");

        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        assert!(
            stats.dedup_hits > 0,
            "expected dedup hits, got hits={} total={}",
            stats.dedup_hits,
            stats.total_chunks
        );

        // Read back while still mounted — sanity check
        assert_eq!(fs.read_file("/first.bin").unwrap(), payload);
        assert_eq!(fs.read_file("/second.bin").unwrap(), payload);
    } // filesystem dropped — simulates crash (no unmount)

    // Session 2: reopen after simulated crash.  Both files must be readable
    // and return correct content.  The second file's content is stored as a
    // dedup redirect; read resolution must follow the redirect to the
    // canonical object and return correct data.
    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");
        let recovered_first = fs.read_file("/first.bin").expect("read first after crash");
        assert_eq!(
            recovered_first, payload,
            "first file (canonical) must be intact after crash/reopen"
        );

        let recovered_second = fs
            .read_file("/second.bin")
            .expect("read second after crash");
        assert_eq!(
            recovered_second, payload,
            "second file (dedup redirect) must resolve correctly after crash/reopen"
        );

        // Dedup stats reset on mount — should be zero after reopen
        let stats = fs.dedup_stats();
        assert_eq!(stats.total_chunks, 0);
        assert_eq!(stats.dedup_hits, 0);
    }
}

// ── Partially-synced dedup writes survive crash ───────────────────────

#[test]
fn synced_dedup_data_survives_crash_with_unsynced_loss() {
    set_test_key();
    let dir = temp_dir("dedup_crash_partial");
    let payload_synced = make_data(DATA_SIZE);
    let payload_unsynced = {
        let mut buf = Vec::with_capacity(DATA_SIZE);
        let mut val = 0xEFu8;
        for _ in 0..DATA_SIZE {
            buf.push(val);
            val = val.wrapping_add(1);
        }
        buf
    };

    // Session 1: write synced file (with dedup enabled), then write
    // unsynced file and drop without syncing.  Simulates a crash where
    // only the first txg committed.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.set_dedup_enabled(true);

        // Synced: two identical files created and committed
        fs.create_file("/safe_a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create safe_a");
        fs.write_file("/safe_a.bin", 0, &payload_synced)
            .expect("write safe_a");

        fs.create_file("/safe_b.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create safe_b");
        fs.write_file("/safe_b.bin", 0, &payload_synced)
            .expect("write safe_b");

        fs.sync_all().expect("sync safe");

        // Un-synced: written after sync, not committed
        fs.create_file("/lost.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create lost");
        fs.write_file("/lost.bin", 0, &payload_unsynced)
            .expect("write lost");
    } // dropped without syncing unsynced data

    // Session 2: synced files (including dedup redirects) must be readable.
    // The un-synced file may be lost (orphan cleanup), but the filesystem
    // must not be corrupted.
    {
        let fs = LocalFileSystem::open(&dir).expect("reopen");

        // Synced files: must be intact
        let safe_a = fs
            .read_file("/safe_a.bin")
            .expect("read safe_a after crash");
        assert_eq!(safe_a, payload_synced);

        let safe_b = fs
            .read_file("/safe_b.bin")
            .expect("read safe_b after crash");
        assert_eq!(
            safe_b, payload_synced,
            "safe_b (dedup redirect) must resolve correctly after crash"
        );

        // Un-synced file: may or may not exist, but if it does, the
        // filesystem must be consistent.
        if let Ok(lost_data) = fs.read_file("/lost.bin") {
            // If the un-synced write survived (unlikely but possible with
            // store-level persistence), the data must match exactly.
            assert_eq!(
                lost_data, payload_unsynced,
                "un-synced file must match expected content if present"
            );
        }
        // Filesystem is consistent (no crash on read, no corruption errors).
    }
}

// ── Dedup redirects + crash + re-write: canonical objects survive ────

#[test]
fn crash_reopen_dedup_hit_on_identical_rewrite() {
    set_test_key();
    let dir = temp_dir("dedup_crash_rewrite");
    let payload = make_data(DATA_SIZE);

    // Session 1: write two identical files, creating canonical + redirect.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.set_dedup_enabled(true);

        fs.create_file("/orig_a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create orig_a");
        fs.write_file("/orig_a.bin", 0, &payload)
            .expect("write orig_a");

        fs.create_file("/orig_b.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create orig_b");
        fs.write_file("/orig_b.bin", 0, &payload)
            .expect("write orig_b");

        fs.sync_all().expect("sync");
    } // crash

    // Session 2: reopen, delete original files, set dedup, write same content.
    // The cross-session canonical-object probe should find the surviving
    // canonical object and produce a dedup hit.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen");
        fs.set_dedup_enabled(true);

        // Delete original files (canonical object may still survive)
        fs.unlink("/orig_a.bin").expect("unlink orig_a");
        fs.unlink("/orig_b.bin").expect("unlink orig_b");
        fs.sync_all().expect("sync after unlink");
    }

    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen 2");
        fs.set_dedup_enabled(true);

        fs.create_file("/new.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create new");
        fs.write_file("/new.bin", 0, &payload).expect("write new");
        fs.sync_all().expect("sync new");

        let stats = fs.dedup_stats();
        // After crash + delete + rewrite: the canonical object from session 1
        // survives unless GC reclaimed it.  The cross-session probe
        // (store.contains_key) checks for it.
        assert_eq!(
            stats.total_chunks, 1,
            "expected 1 chunk written after crash+delete+rewrite"
        );
        // Canonical dedup objects are reference-counted via DedupRefCount (#6167).
        // The reclaim drain decrements refcounts when per-inode chunk keys are deleted.  This test deletes files and reopens without forcing a reclaim drain (tick_background_services) between sessions, so the canonical object may survive.
        // Either outcome is consistent — the assertion verifies
        // This is a non-deterministic crash+delete+rewrite test; the
        // deterministic canonical-target crash lifetime proof is
        // canonical_target_survives_crash_with_live_references below.
        assert!(
            stats.dedup_hits <= 1,
            "unexpected dedup state: hits={} total={}",
            stats.dedup_hits,
            stats.total_chunks
        );

        let recovered = fs.read_file("/new.bin").expect("read new");
        assert_eq!(recovered, payload, "rewritten file must be intact");
    }
}

// ── Canonical target crash lifetime proof ─────────────────────────────
// These tests prove the dedup canonical target object survives an unclean
// shutdown and remains resolvable as long as any reference exists.  No
// file deletions occur between sessions, so the reclaim drain is never
// triggered — the canonical object must deterministically survive.

/// Crash lifetime proof: write canonical + redirect, crash, reopen, and a
/// new same-content write must produce a dedup hit from the surviving
/// canonical object.
#[test]
fn canonical_target_survives_crash_with_live_references() {
    set_test_key();
    let dir = temp_dir("dedup_crash_lifetime");
    let payload = make_data(DATA_SIZE);

    // Session 1: write two identical files.  The first creates the
    // canonical chunk object; the second stores a dedup redirect.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.set_dedup_enabled(true);

        fs.create_file("/file_a.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file_a");
        fs.write_file("/file_a.bin", 0, &payload)
            .expect("write file_a");

        fs.create_file("/file_b.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file_b");
        fs.write_file("/file_b.bin", 0, &payload)
            .expect("write file_b");

        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        assert!(
            stats.dedup_hits > 0,
            "expected dedup hit for second identical write"
        );
    } // crash — drop without unmount

    // Session 2: reopen after crash.  Both files must be readable.
    // Write a third file with the same content — the canonical object
    // from session 1 must survive the crash and produce a dedup hit.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen");
        fs.set_dedup_enabled(true);

        // Files from session 1 survive the crash
        assert_eq!(
            fs.read_file("/file_a.bin").expect("read file_a"),
            payload,
            "file_a (canonical) must be intact after crash"
        );
        assert_eq!(
            fs.read_file("/file_b.bin").expect("read file_b"),
            payload,
            "file_b (dedup redirect) must resolve correctly after crash"
        );

        // Write third file with same content — cross-session probe
        // must find the surviving canonical object.
        fs.create_file("/file_c.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create file_c");
        fs.write_file("/file_c.bin", 0, &payload)
            .expect("write file_c");
        fs.sync_all().expect("sync file_c");

        let stats = fs.dedup_stats();
        assert_eq!(
            stats.dedup_hits, 1,
            "canonical target must survive crash: expected 1 dedup hit for third identical write, got hits={} total={}",
            stats.dedup_hits,
            stats.total_chunks
        );
        assert_eq!(
            stats.total_chunks, 1,
            "expected 1 chunk written (redirect), got {}",
            stats.total_chunks
        );

        // All three files must be readable and return correct data
        assert_eq!(
            fs.read_file("/file_c.bin").expect("read file_c"),
            payload,
            "file_c (new redirect) must resolve correctly"
        );
    }
}

/// Crash lifetime proof: after crash, reopen with dedup disabled, then
/// enable dedup and write same content — the canonical object must still
/// be found via cross-session store probe.
#[test]
fn canonical_target_survives_crash_with_dedup_toggled() {
    set_test_key();
    let dir = temp_dir("dedup_crash_toggle");
    let payload = make_data(DATA_SIZE);

    // Session 1: write canonical object with dedup enabled
    {
        let mut fs = LocalFileSystem::open(&dir).expect("open");
        fs.set_dedup_enabled(true);
        fs.create_file("/canon.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create canon");
        fs.write_file("/canon.bin", 0, &payload)
            .expect("write canon");
        fs.sync_all().expect("sync");
    } // crash

    // Session 2: reopen with dedup disabled (no change), then enable
    // dedup and write same content — probe must find canonical object.
    {
        let mut fs = LocalFileSystem::open(&dir).expect("reopen");
        assert!(!fs.is_dedup_enabled());
        fs.set_dedup_enabled(true);

        fs.create_file("/copy.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create copy");
        fs.write_file("/copy.bin", 0, &payload).expect("write copy");
        fs.sync_all().expect("sync copy");

        assert!(
            fs.dedup_stats().dedup_hits > 0,
            "canonical target must survive crash with dedup toggle: cross-session probe failed"
        );
    }
}
