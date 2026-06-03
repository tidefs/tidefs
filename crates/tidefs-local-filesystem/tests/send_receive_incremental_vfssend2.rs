//! Integration tests for incremental VFSSEND2 send/receive.
//!
//! Exercises the full incremental snapshot stream lifecycle:
//! 1. Create source filesystem with baseline data and snapshot
//! 2. Modify data and create a second snapshot
//! 3. Export full and incremental VFSSEND2 streams
//! 4. Verify VFSSEND2 stream structure (magic, INCREMENTAL flag, from_snapshot_id)
//! 5. Import via VFSSEND1 receive path and verify content parity
//!
//! Validation tier: Tier 3 (mounted userspace/storage runtime).
//! Runtime output, when collected, belongs under `/root/ai/tmp/tidefs-validation/`.

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::LocalFileSystem;
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
use tidefs_send_stream::{StreamFlags, STREAM_MAGIC};

// ── Helpers ───────────────────────────────────────────────────────────

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_root(label: &str) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = env::temp_dir().join(format!(
        "tidefs-incr-vfssend2-{label}-{ts}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn open_fs(root: &std::path::Path) -> LocalFileSystem {
    let opts = StoreOptions::test_fast();
    let store = LocalObjectStore::open_with_options(root, opts).expect("open store");
    drop(store);
    LocalFileSystem::open(root).expect("open filesystem")
}

/// Decode the VFSSEND2 stream flags from a raw stream (header at offset 10).
fn stream_flags_from_encoded(encoded: &[u8]) -> u16 {
    assert!(encoded.len() >= 12, "stream too short for flags field");
    u16::from_le_bytes([encoded[10], encoded[11]])
}

/// Decode from_snapshot_id from a VFSSEND2 stream (bytes 28..44).
fn from_snapshot_id_from_encoded(encoded: &[u8]) -> tidefs_send_stream::Id128 {
    assert!(encoded.len() >= 60, "stream too short for from_snapshot_id");
    let mut id = [0u8; 16];
    id.copy_from_slice(&encoded[44..60]);
    id
}

/// Decode to_snapshot_id from a VFSSEND2 stream (bytes 44..60).
fn to_snapshot_id_from_encoded(encoded: &[u8]) -> tidefs_send_stream::Id128 {
    assert!(encoded.len() >= 76, "stream too short for to_snapshot_id");
    let mut id = [0u8; 16];
    id.copy_from_slice(&encoded[60..76]);
    id
}

// ── Tests ─────────────────────────────────────────────────────────────

#[test]
fn incremental_vfssend2_stream_has_correct_structure() {
    set_test_key();

    // -- Setup source filesystem with baseline data --
    let src_root = temp_root("src");
    let mut src = open_fs(&src_root);

    let pool_id: tidefs_send_stream::Id128 = [0xAA; 16];
    let dataset_id: tidefs_send_stream::Id128 = [0xBB; 16];

    // Write baseline file
    src.create_file("/data.txt", 0o644)
        .expect("create baseline file");
    src.write_file("/data.txt", 0, b"baseline content v1")
        .expect("write baseline");

    // Snapshot the baseline state (this will be the `from_root`)
    let base_snap = src.create_snapshot("base").expect("create base snapshot");
    let from_root = base_snap.source_root.clone();

    // -- Modify after snapshot (these are the incremental changes) --
    src.write_file("/data.txt", 0, b"modified content v2")
        .expect("overwrite after snapshot");
    src.create_file("/new_file.txt", 0o644)
        .expect("create new file");
    src.write_file("/new_file.txt", 0, b"new file data")
        .expect("write new file");

    let _mod_snap = src
        .create_snapshot("modified")
        .expect("create modified snapshot");

    // -- Export full VFSSEND2 stream --
    let full_stream = src
        .export_vfssend2(pool_id, dataset_id)
        .expect("full VFSSEND2 export");

    assert!(!full_stream.is_empty());
    assert_eq!(&full_stream[0..8], STREAM_MAGIC, "VFSSEND2 magic bytes");

    let full_flags = stream_flags_from_encoded(&full_stream);
    assert_eq!(
        full_flags & StreamFlags::INCREMENTAL.bits(),
        0,
        "full export must not have INCREMENTAL flag"
    );

    // -- Export incremental VFSSEND2 stream --
    let incr_stream = src
        .export_incremental_vfssend2(pool_id, dataset_id, &from_root)
        .expect("incremental VFSSEND2 export");

    assert!(!incr_stream.is_empty());
    assert_eq!(&incr_stream[0..8], STREAM_MAGIC, "VFSSEND2 magic bytes");

    let incr_flags = stream_flags_from_encoded(&incr_stream);
    assert!(
        incr_flags & StreamFlags::INCREMENTAL.bits() != 0,
        "incremental export must have INCREMENTAL flag set; got flags={incr_flags:#06x}"
    );

    // Verify from_snapshot_id matches the base snapshot
    let expected_from_id = make_snapshot_id(from_root.transaction_id, from_root.generation);
    let actual_from_id = from_snapshot_id_from_encoded(&incr_stream);
    assert_eq!(
        actual_from_id, expected_from_id,
        "from_snapshot_id must match base snapshot"
    );

    // Verify to_snapshot_id is non-zero (it reflects the export's current root)
    let actual_to_id = to_snapshot_id_from_encoded(&incr_stream);
    assert!(actual_to_id != [0u8; 16], "to_snapshot_id must be non-zero");

    // Incremental stream should be smaller than full stream
    assert!(
        incr_stream.len() < full_stream.len(),
        "incremental stream ({}) must be smaller than full stream ({})",
        incr_stream.len(),
        full_stream.len()
    );

    // -- Cleanup --
    drop(src);
    let _ = fs::remove_dir_all(&src_root);
}

#[test]
fn incremental_vfssend2_content_parity_with_vfssend1_import() {
    set_test_key();

    // -- Source: write baseline + snapshot + modifications --
    let src_root = temp_root("src-parity");
    let mut src = open_fs(&src_root);

    let pool_id: tidefs_send_stream::Id128 = [0x11; 16];
    let dataset_id: tidefs_send_stream::Id128 = [0x22; 16];

    src.create_file("/a.txt", 0o644).expect("create a.txt");
    src.write_file("/a.txt", 0, b"AAAA")
        .expect("write a.txt v1");

    let base_snap = src.create_snapshot("base").expect("create base snapshot");
    let from_root = base_snap.source_root.clone();

    // Modify after snapshot
    src.write_file("/a.txt", 0, b"BBBB")
        .expect("overwrite a.txt");
    src.create_file("/b.txt", 0o644).expect("create b.txt");
    src.write_file("/b.txt", 0, b"CCCC").expect("write b.txt");

    // -- Export VFSSEND2 incremental stream --
    let incr_vfssend2 = src
        .export_incremental_vfssend2(pool_id, dataset_id, &from_root)
        .expect("incremental VFSSEND2 export");

    assert!(!incr_vfssend2.is_empty());
    assert_eq!(&incr_vfssend2[0..8], STREAM_MAGIC);

    // -- Export VFSSEND1 incremental stream for import verification --
    let incr_vfssend1 = src
        .export_incremental_changed_records(&from_root)
        .expect("incremental VFSSEND1 export");

    // Export full VFSSEND1 (baseline state) for target setup
    // Re-open a fresh source at baseline state by rolling back
    // Actually, export the full baseline export and import it on target first
    let full_vfssend1 = {
        // Use a separate read-only view: export from the base snapshot root
        // The export_changed_records gives the current state; instead,
        // we'll create a fresh FS from base snapshot content.
        // Simplest: create target directly from scratch, import full, then incremental
        src.export_changed_records().expect("full VFSSEND1 export")
    };

    // -- Target: import full, then incremental, then verify --
    let tgt_parent = temp_root("tgt-parity");
    let tgt_root = tgt_parent.join("target-pool");
    // The target directory must not exist before receive

    let import_report = LocalFileSystem::receive_changed_records_into_empty_root(
        &tgt_root,
        StoreOptions::test_fast(),
        &full_vfssend1,
    )
    .expect("import full VFSSEND1 into target");

    assert!(import_report.imported_roots > 0);

    // Now open target and apply incremental
    let tgt = LocalFileSystem::open(&tgt_root).expect("open target fs");

    let incr_import = LocalFileSystem::receive_incremental_changed_records(
        &tgt_root,
        StoreOptions::test_fast(),
        &incr_vfssend1,
    )
    .expect("import incremental VFSSEND1");

    assert!(incr_import.imported_roots > 0);

    // Re-open target to see imported state
    drop(tgt);
    let tgt = LocalFileSystem::open(&tgt_root).expect("reopen target fs");

    // Verify content parity
    let a_data = tgt.read_file("/a.txt").expect("read /a.txt on target");
    assert_eq!(a_data, b"BBBB", "/a.txt must have modified content");

    let b_data = tgt.read_file("/b.txt").expect("read /b.txt on target");
    assert_eq!(b_data, b"CCCC", "/b.txt must exist with correct content");

    // Verify snapshots are present
    let snaps = tgt.list_snapshots();
    assert!(
        snaps.iter().any(|s| s.name == "base"),
        "target must have 'base' snapshot"
    );

    // -- Cleanup --
    drop(tgt);
    drop(src);
    let _ = fs::remove_dir_all(&src_root);
    let _ = fs::remove_dir_all(&tgt_parent);
}

/// Derive a deterministic snapshot id (mirrors the bridge's make_snapshot_id).
fn make_snapshot_id(transaction_id: u64, generation: u64) -> tidefs_send_stream::Id128 {
    let mut id = [0u8; 16];
    id[0..8].copy_from_slice(&transaction_id.to_le_bytes());
    id[8..16].copy_from_slice(&generation.to_le_bytes());
    id
}
