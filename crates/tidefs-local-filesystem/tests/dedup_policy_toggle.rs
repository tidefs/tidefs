// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Policy-toggle validation for content-addressed chunk dedup (#5966).
//!
//! Verifies that the `org.tidefs:dedup` feature flag controls whether chunk
//! writes produce dedup redirects or inline chunk data.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{LocalFileSystem, DEFAULT_FILE_PERMISSIONS};

const CHUNK_SIZE: usize = 65536; // DEFAULT_FILESYSTEM_CONTENT_CHUNK_SIZE
const DATA_SIZE: usize = CHUNK_SIZE * 2; // two chunks to exercise multiple chunks

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!("tidefs-dedup-{label}-{ts}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(dir: &std::path::Path) -> LocalFileSystem {
    LocalFileSystem::open(dir).expect("open filesystem")
}

fn make_pattern_data(seed: u8, len: usize) -> Vec<u8> {
    let mut buf = Vec::with_capacity(len);
    let mut val = seed;
    for _ in 0..len {
        buf.push(val);
        val = val.wrapping_add(1);
    }
    buf
}

// ── Dedup enabled: identical content produces dedup hits ──────────────

#[test]
fn dedup_enabled_produces_hits_for_duplicate_content() {
    set_test_key();
    let dir = temp_dir("dedup_enabled_hits");
    let payload = make_pattern_data(0xCD, DATA_SIZE);

    {
        let mut fs = open_fs(&dir);
        fs.set_dedup_enabled(true);
        assert!(fs.is_dedup_enabled());

        // First file: writes all chunks as canonical objects
        fs.create_file("/first.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create first");
        fs.write_file("/first.bin", 0, &payload)
            .expect("write first");

        // Second file: identical content should produce dedup redirects
        fs.create_file("/second.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create second");
        fs.write_file("/second.bin", 0, &payload)
            .expect("write second");

        fs.sync_all().expect("sync");

        let stats = fs.dedup_stats();
        assert!(
            stats.dedup_hits > 0,
            "expected dedup_hits > 0 with dedup enabled, got dedup_hits={} total_chunks={}",
            stats.dedup_hits,
            stats.total_chunks
        );
        assert!(
            stats.dedup_bytes_saved > 0,
            "expected dedup_bytes_saved > 0"
        );
        assert_eq!(stats.total_chunks, 4); // 2 chunks × 2 files

        // Verify both files read back correctly
        let data1 = fs.read_file("/first.bin").expect("read first");
        assert_eq!(data1, payload, "first file content mismatch");
        let data2 = fs.read_file("/second.bin").expect("read second");
        assert_eq!(data2, payload, "second file content mismatch");
    }

    // Reopen with dedup disabled — data must still be readable
    {
        let fs = open_fs(&dir);
        assert!(
            !fs.is_dedup_enabled(),
            "dedup should be off by default on reopen"
        );
        let data1 = fs.read_file("/first.bin").expect("read first after reopen");
        assert_eq!(data1, payload);
        let data2 = fs
            .read_file("/second.bin")
            .expect("read second after reopen");
        assert_eq!(data2, payload);
    }
}

// ── Dedup disabled (default): no hits for duplicate content ───────────

#[test]
fn dedup_disabled_produces_no_hits() {
    set_test_key();
    let dir = temp_dir("dedup_disabled_no_hits");
    let payload = make_pattern_data(0xEF, DATA_SIZE);

    {
        let mut fs = open_fs(&dir);
        assert!(!fs.is_dedup_enabled(), "dedup should be off by default");

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
        assert_eq!(
            stats.dedup_hits, 0,
            "expected dedup_hits == 0 with dedup disabled, got dedup_hits={}",
            stats.dedup_hits
        );
        assert_eq!(
            stats.dedup_bytes_saved, 0,
            "expected dedup_bytes_saved == 0 with dedup disabled"
        );
        // Total chunks should be 4 (2 chunks × 2 files), all inline
        assert_eq!(stats.total_chunks, 4);

        // Verify both files read back correctly
        let data1 = fs.read_file("/first.bin").expect("read first");
        assert_eq!(data1, payload, "first file content mismatch");
        let data2 = fs.read_file("/second.bin").expect("read second");
        assert_eq!(data2, payload, "second file content mismatch");
    }
}

// ── Toggle mid-session: enabling after writes only affects future writes ─

#[test]
fn toggle_mid_session_only_affects_future_writes() {
    set_test_key();
    let dir = temp_dir("dedup_mid_session");
    let payload_a = make_pattern_data(0x11, DATA_SIZE);
    let payload_b = make_pattern_data(0x22, DATA_SIZE);

    let mut fs = open_fs(&dir);
    assert!(!fs.is_dedup_enabled());

    // Write with dedup disabled
    fs.create_file("/before_a.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create before_a");
    fs.write_file("/before_a.bin", 0, &payload_a)
        .expect("write before_a");
    fs.create_file("/before_b.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create before_b");
    fs.write_file("/before_b.bin", 0, &payload_a)
        .expect("write before_b"); // same content

    let stats_before = fs.dedup_stats();
    assert_eq!(
        stats_before.dedup_hits, 0,
        "no hits expected before enabling"
    );

    // Enable dedup
    fs.set_dedup_enabled(true);
    assert!(fs.is_dedup_enabled());

    // Write with dedup enabled (new content, not yet canonicalized)
    fs.create_file("/after_a.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create after_a");
    fs.write_file("/after_a.bin", 0, &payload_b)
        .expect("write after_a");
    fs.create_file("/after_b.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create after_b");
    fs.write_file("/after_b.bin", 0, &payload_b)
        .expect("write after_b"); // duplicate

    fs.sync_all().expect("sync");

    let stats = fs.dedup_stats();
    // The DedupIndex is empty when dedup was enabled (no cross-session persistence),
    // so the first chunk of after_a becomes canonical, the matching chunk in after_b is a hit.
    assert!(
        stats.dedup_hits > 0,
        "expected hits after enabling dedup, got dedup_hits={}",
        stats.dedup_hits
    );

    // Verify all files readable
    assert_eq!(fs.read_file("/before_a.bin").unwrap(), payload_a);
    assert_eq!(fs.read_file("/before_b.bin").unwrap(), payload_a);
    assert_eq!(fs.read_file("/after_a.bin").unwrap(), payload_b);
    assert_eq!(fs.read_file("/after_b.bin").unwrap(), payload_b);
}

// ── DedupStats defaults and ratio ────────────────────────────────────

#[test]
fn dedup_stats_defaults_and_ratio() {
    set_test_key();
    let dir = temp_dir("dedup_stats_ratio");
    let payload = make_pattern_data(0x99, CHUNK_SIZE); // exactly one chunk

    let mut fs = open_fs(&dir);

    // Before any writes, stats should be zero
    let s0 = fs.dedup_stats();
    assert_eq!(s0.dedup_hits, 0);
    assert_eq!(s0.total_chunks, 0);
    assert_eq!(s0.dedup_bytes_saved, 0);

    fs.set_dedup_enabled(true);

    // Write first file
    fs.create_file("/unique.bin", DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.write_file("/unique.bin", 0, &payload).unwrap();
    fs.create_file("/dupe.bin", DEFAULT_FILE_PERMISSIONS)
        .unwrap();
    fs.write_file("/dupe.bin", 0, &payload).unwrap(); // duplicate

    fs.sync_all().unwrap();

    let stats = fs.dedup_stats();
    // 2 total chunks, 1 dedup hit
    assert_eq!(stats.total_chunks, 2);
    assert_eq!(stats.dedup_hits, 1);
    assert_eq!(stats.dedup_bytes_saved, CHUNK_SIZE as u64);
    // ratio = 2 / (2 - 1) = 2.0
    assert!(
        (stats.dedup_ratio() - 2.0).abs() < 1e-9,
        "expected dedup_ratio ≈ 2.0, got {}",
        stats.dedup_ratio()
    );
}
