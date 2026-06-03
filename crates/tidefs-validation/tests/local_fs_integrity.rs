#![cfg(feature = "fuse")]

//! Local-filesystem integrity integration tests.
//!
//! Exercises the LocalFileSystem → LocalObjectStore pipeline end-to-end:
//! BLAKE3 checksum tree verification through the composed stack, and
//! read-after-write byte-for-byte consistency within a single session.
//!
//! No FUSE mount required — these tests exercise the in-memory harness
//! directly against the [`tidefs_local_filesystem::LocalFileSystem`] API.
//!
//! Filters:
//! - `cargo test -p tidefs-validation --features fuse -- local_fs`
//! - `cargo test -p tidefs-validation --features fuse -- blake3`

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tidefs_local_filesystem::{
    content_object_key_for_version, LocalFileSystem, RootAuthenticationKey,
    DEFAULT_FILE_PERMISSIONS,
};
use tidefs_local_object_store::StoreOptions;

// ── Helpers ──────────────────────────────────────────────────────────────

fn temp_root(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-lfs-int-{label}-{}-{nanos}",
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

fn open_fs(root: &Path) -> LocalFileSystem {
    LocalFileSystem::open_with_root_authentication_key(root, store_opts(), auth_key())
        .expect("open LocalFileSystem")
}

/// Deterministic incrementing byte sequence: 0, 1, 2, … wrapping at 256.
fn seq_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

/// All-zeroes byte buffer.
fn zero_data(len: usize) -> Vec<u8> {
    vec![0u8; len]
}

/// All-ones byte buffer (0xFF repeated).
fn ones_data(len: usize) -> Vec<u8> {
    vec![0xFFu8; len]
}

/// Alternating 0xAA / 0x55 pattern.
fn alternating_data(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| if i % 2 == 0 { 0xAAu8 } else { 0x55u8 })
        .collect()
}

/// Verify the BLAKE3 checksum tree for a file exists and verifies correctly.
/// Uses the versioned content object key derived from the inode record.
fn assert_file_blake3_tree_verifies(fs: &LocalFileSystem, path: &str) {
    let rec = fs.stat(path).expect("stat");
    let store = fs.object_store();
    let versioned_key = content_object_key_for_version(rec.inode_id, rec.data_version);

    let tree = store
        .get_checksum_tree(versioned_key, 4096)
        .expect("get_checksum_tree")
        .expect("checksum tree must exist for versioned content key");
    let verified = store
        .verify_checksum_tree(versioned_key, &tree)
        .expect("verify_checksum_tree");
    assert!(
        verified,
        "BLAKE3 checksum tree must verify intact data for {path}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 1: BLAKE3 Integrity through the local filesystem stack
// ═══════════════════════════════════════════════════════════════════════════

/// Write a known data pattern through LocalFileSystem, fsync, then verify
/// the BLAKE3 checksum tree matches the stored content via the object store.
/// Uses an alternating 0xAA/0x55 pattern (4 KiB).
#[test]
fn local_fs_blake3_integrity_alternating_4kib() {
    let root = temp_root("blake3-alt");
    cleanup(&root);

    let data = alternating_data(4096);
    let path = "/blake3-alt.bin";

    {
        let mut fs = open_fs(&root);
        fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.replace_file(path, &data).expect("write");
        fs.fsync_file(path).expect("fsync");

        // Read-back through LocalFileSystem must match.
        let read_back = fs.read_file(path).expect("read_file");
        assert_eq!(
            read_back, data,
            "local-fs read-back must match written data"
        );

        // Verify BLAKE3 checksum tree through the object store.
        assert_file_blake3_tree_verifies(&fs, path);
    }

    {
        // Reopen and verify data + checksum survived.
        let fs = open_fs(&root);
        let read_back = fs.read_file(path).expect("read after reopen");
        assert_eq!(read_back, data, "data must survive reopen byte-for-byte");

        assert_file_blake3_tree_verifies(&fs, path);
    }

    cleanup(&root);
}

/// Write files with varied data patterns (all-zeroes, all-ones,
/// sequenced) through LocalFileSystem and verify BLAKE3 checksum trees
/// independently for each pattern.
#[test]
fn local_fs_blake3_integrity_varied_patterns() {
    let root = temp_root("blake3-var");
    cleanup(&root);

    let patterns: [(&str, Vec<u8>); 3] = [
        ("/zeros.bin", zero_data(8192)),
        ("/ones.bin", ones_data(8192)),
        ("/seq.bin", seq_data(8192)),
    ];

    {
        let mut fs = open_fs(&root);
        for (path, data) in &patterns {
            fs.create_file(path, DEFAULT_FILE_PERMISSIONS)
                .expect("create_file");
            fs.replace_file(path, data).expect("write");
            fs.fsync_file(path).expect("fsync");
        }
        fs.sync_all().expect("sync_all");

        for (path, data) in &patterns {
            // Read-back verification.
            let read_back = fs.read_file(path).expect("read_file");
            assert_eq!(&read_back, data, "byte-for-byte mismatch for {path}");

            // BLAKE3 checksum tree verification.
            assert_file_blake3_tree_verifies(&fs, path);
        }
    }

    cleanup(&root);
}

/// Write an empty file through LocalFileSystem and verify the BLAKE3
/// checksum tree handles zero-length content correctly.
#[test]
fn local_fs_blake3_integrity_empty_file() {
    let root = temp_root("blake3-empty");
    cleanup(&root);

    {
        let mut fs = open_fs(&root);
        fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create_file");
        fs.fsync_file("/empty.bin").expect("fsync empty");

        let rec = fs.stat("/empty.bin").expect("stat");
        let versioned_key = content_object_key_for_version(rec.inode_id, rec.data_version);
        let store = fs.object_store();
        // Zero-length content: tree may or may not exist depending on
        // whether the object store writes an empty payload. Verify
        // read-back is correct either way.
        if let Ok(Some(tree)) = store.get_checksum_tree(versioned_key, 4096) {
            let verified = store
                .verify_checksum_tree(versioned_key, &tree)
                .expect("verify_checksum_tree empty");
            assert!(verified, "BLAKE3 tree must verify empty content");
        }

        let read_back = fs.read_file("/empty.bin").expect("read empty");
        assert!(read_back.is_empty(), "empty file must be empty on read");
    }

    cleanup(&root);
}

// ═══════════════════════════════════════════════════════════════════════════
// Category 2: Read-after-write consistency
// ═══════════════════════════════════════════════════════════════════════════

/// Write 1 byte, immediately read back, verify byte-for-byte equality.
#[test]
fn local_fs_read_after_write_1byte() {
    let root = temp_root("raw-1b");
    cleanup(&root);

    let data = vec![0x7Fu8; 1];

    let mut fs = open_fs(&root);
    fs.create_file("/tiny.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.replace_file("/tiny.bin", &data).expect("write 1 byte");

    let read_back = fs.read_file("/tiny.bin").expect("read_file");
    assert_eq!(read_back, data, "1-byte read-after-write mismatch");

    let rec = fs.stat("/tiny.bin").expect("stat");
    assert_eq!(rec.size, 1, "file size should be 1 byte after write");

    cleanup(&root);
}

/// Write a block-aligned (4 KiB) payload, immediately read back, verify
/// byte-for-byte equality.
#[test]
fn local_fs_read_after_write_block_aligned_4kib() {
    let root = temp_root("raw-4k");
    cleanup(&root);

    let data = seq_data(4096);

    let mut fs = open_fs(&root);
    fs.create_file("/aligned.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.replace_file("/aligned.bin", &data).expect("write");

    let read_back = fs.read_file("/aligned.bin").expect("read_file");
    assert_eq!(
        read_back, data,
        "4 KiB block-aligned read-after-write mismatch"
    );

    let rec = fs.stat("/aligned.bin").expect("stat");
    assert_eq!(
        rec.size, 4096,
        "file size should be 4096 bytes after block-aligned write"
    );

    cleanup(&root);
}

/// Write a block-unaligned (4097 bytes) payload, immediately read back,
/// verify byte-for-byte equality.
#[test]
fn local_fs_read_after_write_block_unaligned_4097() {
    let root = temp_root("raw-4k1");
    cleanup(&root);

    let data = alternating_data(4097);

    let mut fs = open_fs(&root);
    fs.create_file("/unaligned.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.replace_file("/unaligned.bin", &data).expect("write");

    let read_back = fs.read_file("/unaligned.bin").expect("read_file");
    assert_eq!(
        read_back, data,
        "4097-byte block-unaligned read-after-write mismatch"
    );

    let rec = fs.stat("/unaligned.bin").expect("stat");
    assert_eq!(
        rec.size, 4097,
        "file size should be 4097 bytes after unaligned write"
    );

    cleanup(&root);
}

/// Write multi-block spanning data (64 KiB), immediately read back,
/// verify byte-for-byte equality.
#[test]
fn local_fs_read_after_write_multi_block_64kib() {
    let root = temp_root("raw-64k");
    cleanup(&root);

    let data = seq_data(65536);

    let mut fs = open_fs(&root);
    fs.create_file("/big.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    fs.replace_file("/big.bin", &data).expect("write");

    let read_back = fs.read_file("/big.bin").expect("read_file");
    assert_eq!(
        read_back, data,
        "64 KiB multi-block read-after-write mismatch"
    );

    let rec = fs.stat("/big.bin").expect("stat");
    assert_eq!(
        rec.size, 65536,
        "file size should be 65536 bytes after multi-block write"
    );

    cleanup(&root);
}

/// Verify unwritten regions read as zeroes.
/// Write 1 KiB at offset 0, truncate-extend to 4 KiB,
/// verify bytes 1024..4096 read as zeroes (sparse region semantics).
#[test]
fn local_fs_read_after_write_sparse_region_zeroes() {
    let root = temp_root("raw-sparse");
    cleanup(&root);

    let data = ones_data(1024); // 1 KiB of 0xFF at offset 0

    let mut fs = open_fs(&root);
    fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    // write_file writes at a specific offset without truncating.
    fs.write_file("/sparse.bin", 0, &data)
        .expect("write at offset 0");

    let read_back = fs.read_file("/sparse.bin").expect("read_file");
    assert_eq!(
        read_back.len(),
        1024,
        "file should be exactly 1 KiB (write_file at offset 0)"
    );

    // First 1024 bytes must match written data.
    assert_eq!(
        &read_back[..1024],
        &data,
        "first 1 KiB must match written data"
    );

    // Extend to 4 KiB via truncate and verify zero-fill.
    fs.truncate_file("/sparse.bin", 4096)
        .expect("truncate to 4 KiB");
    let extended = fs.read_file("/sparse.bin").expect("read extended");
    assert_eq!(extended.len(), 4096, "extended file should be 4 KiB");
    assert_eq!(
        &extended[..1024],
        &data,
        "first 1 KiB must survive truncate-extend unchanged"
    );

    // Bytes 1024..4096 must be zero-filled.
    for i in 1024..4096 {
        assert_eq!(
            extended[i], 0u8,
            "byte at offset {i} should be zero-filled after extend; got 0x{:02x}",
            extended[i]
        );
    }

    cleanup(&root);
}

/// Write an empty file (zero-length) and verify read-back is empty.
#[test]
fn local_fs_read_after_write_empty_file() {
    let root = temp_root("raw-empty");
    cleanup(&root);

    let mut fs = open_fs(&root);
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create_file");
    // replace_file with empty payload.
    fs.replace_file("/empty.bin", &[]).expect("write empty");

    let read_back = fs.read_file("/empty.bin").expect("read_file");
    assert!(read_back.is_empty(), "empty file must read back as empty");

    let rec = fs.stat("/empty.bin").expect("stat");
    assert_eq!(rec.size, 0, "empty file size must be 0");

    cleanup(&root);
}
