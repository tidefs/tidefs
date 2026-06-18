// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration validation tests for extent-map transaction persistence.
//!
//! Exercises the TransactionExtentMap manifest role (#7) and
//! ChangedRecordObjectRole::TransactionExtentMap variant (#8) through
//! local-filesystem transactions and object-store round-trips.
use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_local_filesystem::{ChangedRecordObjectRole, LocalFileSystem, DEFAULT_FILE_PERMISSIONS};
use tidefs_local_object_store::StoreOptions;

// ── helpers ──

fn set_test_key() {
    std::env::set_var("TIDEFS_ROOT_AUTHENTICATION_KEY_HEX", "A".repeat(64));
}

fn temp_dir(label: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("tidefs-extmap-txn-{label}"));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn test_options() -> StoreOptions {
    StoreOptions::test_fast()
}

fn cleanup(dir: &PathBuf) {
    let _ = fs::remove_dir_all(dir);
}

// ───────────────────────────────────────────────────────────────
// Test 1: Allocate extent in transaction, commit, verify lookup
// ───────────────────────────────────────────────────────────────

#[test]
fn txn_allocate_extent_commit_and_lookup() {
    set_test_key();
    let root = temp_dir("txn-alloc-lookup");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    // Begin transaction, create file, write data (triggers extent allocation).
    fs.begin_transaction().expect("begin transaction");
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create data.bin");
    fs.write_file("/data.bin", 0, &vec![0xABu8; 8192])
        .expect("write 8 KiB");
    fs.commit_transaction().expect("commit transaction");

    // After commit, extent should be visible via lookup_extents.
    let inode_id = fs.lookup("/data.bin").expect("lookup inode");
    let ino = inode_id.get();

    let extents = fs.lookup_extents(ino, 0, 16384);
    assert!(
        !extents.is_empty(),
        "extent should exist after allocate+commit"
    );
    assert_eq!(extents.len(), 1, "one contiguous extent for 8 KiB write");
    assert_eq!(extents[0].logical_offset, 0);
    assert_eq!(extents[0].length, 8192);
    assert!(extents[0].is_pending_data());

    // Read the data back via the regular filesystem path.
    let data = fs.read_file("/data.bin").expect("read data.bin");
    assert_eq!(data.len(), 8192);
    assert_eq!(&data[0..4], &[0xABu8; 4]);

    // Verify extent map records exist in the changed record export.
    let export = fs.export_changed_records().expect("export changed records");
    let has_ext_map_role = export.roots.iter().any(|root| {
        root.records
            .iter()
            .any(|r| r.role == ChangedRecordObjectRole::TransactionExtentMap)
    });
    assert!(
        has_ext_map_role,
        "changed record export must contain TransactionExtentMap entries"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn txn_allocate_multiple_non_contiguous_extents() {
    set_test_key();
    let root = temp_dir("txn-alloc-multi");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin transaction");
    fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create sparse.bin");
    // Write at offset 0 (one extent)
    fs.write_file("/sparse.bin", 0, &[0x11u8; 4096])
        .expect("write at 0");
    // Write at offset 16384 (non-contiguous, second extent)
    fs.write_file("/sparse.bin", 16384, &[0x22u8; 4096])
        .expect("write at 16384");
    fs.commit_transaction().expect("commit transaction");

    let inode_id = fs.lookup("/sparse.bin").expect("lookup inode");
    let ino = inode_id.get();

    // Look up across the full logical range.
    let extents = fs.lookup_extents(ino, 0, 24576);
    assert_eq!(extents.len(), 2, "two non-contiguous extents expected");

    // First extent: [0, 4096)
    assert_eq!(extents[0].logical_offset, 0);
    assert_eq!(extents[0].length, 4096);

    // Second extent: [16384, 20480)
    assert_eq!(extents[1].logical_offset, 16384);
    assert_eq!(extents[1].length, 4096);

    // Verify gap at [4096, 16384) has no extent.
    let gap = fs.lookup_extents(ino, 4096, 12288);
    assert!(gap.is_empty(), "gap should have no extents");

    drop(fs);
    cleanup(&root);
}

// ───────────────────────────────────────────────────────────────
// Test 2: Allocate, commit, free, commit, verify gone
// ───────────────────────────────────────────────────────────────

#[test]
fn txn_allocate_commit_free_commit_verify_gone() {
    set_test_key();
    let root = temp_dir("txn-alloc-free");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    // Allocate extent.
    fs.begin_transaction().expect("begin tx 1");
    fs.create_file("/temp.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create temp.bin");
    fs.write_file("/temp.bin", 0, &[0xCCu8; 4096])
        .expect("write temp.bin");
    fs.commit_transaction().expect("commit tx 1");

    let inode_id = fs.lookup("/temp.bin").expect("lookup inode");
    let ino = inode_id.get();

    // Verify extent exists.
    let extents_before = fs.lookup_extents(ino, 0, 8192);
    assert!(!extents_before.is_empty(), "extent must exist before free");

    // Free extent: truncate to zero removes allocation.
    fs.begin_transaction().expect("begin tx 2");
    fs.truncate_file("/temp.bin", 0).expect("truncate to 0");
    fs.commit_transaction().expect("commit tx 2");

    // Verify extent is gone.
    let extents_after = fs.lookup_extents(ino, 0, 8192);
    assert!(
        extents_after.is_empty(),
        "extent should be gone after truncate to 0"
    );

    // File content should also be empty.
    let data = fs.read_file("/temp.bin").expect("read temp.bin");
    assert!(
        data.is_empty(),
        "file content should be empty after truncate"
    );

    // Export changed records and verify we see TransactionExtentMap entries.
    let export = fs.export_changed_records().expect("export changed records");
    assert!(
        !export.roots.is_empty(),
        "export should have at least one root"
    );
    let has_ext_map = export.roots.iter().any(|root| {
        root.records
            .iter()
            .any(|r| r.role == ChangedRecordObjectRole::TransactionExtentMap)
    });
    assert!(
        has_ext_map,
        "changed records must contain TransactionExtentMap"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn txn_allocate_free_via_unlink() {
    set_test_key();
    let root = temp_dir("txn-alloc-free-unlink");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx 1");
    fs.create_file("/doomed.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create doomed.bin");
    fs.write_file("/doomed.bin", 0, &[0xDDu8; 8192])
        .expect("write doomed.bin");
    fs.commit_transaction().expect("commit tx 1");

    let inode_id = fs.lookup("/doomed.bin").expect("lookup inode");
    let ino = inode_id.get();
    let extents_before = fs.lookup_extents(ino, 0, 16384);
    assert!(
        !extents_before.is_empty(),
        "extent must exist before unlink"
    );

    // Unlink removes the file and its extents.
    fs.begin_transaction().expect("begin tx 2");
    fs.unlink("/doomed.bin").expect("unlink doomed.bin");
    fs.commit_transaction().expect("commit tx 2");

    // File lookup should fail after unlink.
    assert!(fs.lookup("/doomed.bin").is_err());

    // Export changed records: should reflect the unlink in the transaction log.
    let export = fs.export_changed_records().expect("export changed records");
    assert!(
        !export.roots.is_empty(),
        "export should contain transaction roots after unlink"
    );

    drop(fs);
    cleanup(&root);
}

// ───────────────────────────────────────────────────────────────
// Test 3: Data persistence round-trip across reopen
// ───────────────────────────────────────────────────────────────

#[test]
fn extent_map_data_survives_reopen_via_read_path() {
    set_test_key();
    let root = temp_dir("extmap-reopen");

    // Phase 1: Write data with extents, sync, drop.
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
        fs.set_auto_commit(false);

        fs.begin_transaction().expect("begin tx");
        fs.create_file("/persist.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create persist.bin");
        fs.write_file("/persist.bin", 0, &[0xEEu8; 4096])
            .expect("write 4 KiB");
        fs.write_file("/persist.bin", 8192, &[0xFFu8; 4096])
            .expect("write 4 KiB at 8192");
        fs.commit_transaction().expect("commit tx");
        fs.sync_all().expect("sync all");
    }

    // Phase 2: Reopen and verify data (regular read path).
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, test_options()).expect("reopen filesystem");
        let data = fs.read_file("/persist.bin").expect("read persist.bin");
        assert_eq!(
            data.len() as u64,
            8192 + 4096,
            "data size should span both writes"
        );
        assert_eq!(&data[0..4], &[0xEEu8; 4], "first write at offset 0");
        assert_eq!(
            &data[8192..8196],
            &[0xFFu8; 4],
            "second write at offset 8192"
        );

        // Verify directory listing survives.
        let listing = fs.list_dir("/").expect("list root");
        let names: Vec<String> = listing.iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"persist.bin".to_string()));

        // Export changed records from the reopened filesystem to confirm
        // the transaction log includes extent map records.
        let export = fs.export_changed_records().expect("export changed records");
        let has_ext_map = export.roots.iter().any(|root| {
            root.records
                .iter()
                .any(|r| r.role == ChangedRecordObjectRole::TransactionExtentMap)
        });
        assert!(
            has_ext_map,
            "reopened filesystem export must contain TransactionExtentMap records"
        );
    }

    cleanup(&root);
}

// ───────────────────────────────────────────────────────────────
// Test 4: ChangedRecordObjectRole variants for extent-map records
// ───────────────────────────────────────────────────────────────

#[test]
fn changed_record_role_includes_transaction_extent_map() {
    set_test_key();
    let root = temp_dir("changed-record-role");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    // Create and write a file to produce both extent-map and content records.
    fs.begin_transaction().expect("begin tx");
    fs.create_file("/role_test.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create role_test.bin");
    fs.write_file("/role_test.bin", 0, &[0x01u8; 512])
        .expect("write 512 bytes");
    fs.commit_transaction().expect("commit tx");

    // Export changed records and inspect the roles.
    let export = fs.export_changed_records().expect("export changed records");

    // The export should contain a TransactionExtentMap record (role #8).
    let extent_map_records: Vec<_> = export
        .roots
        .iter()
        .flat_map(|root| root.records.iter())
        .filter(|r| r.role == ChangedRecordObjectRole::TransactionExtentMap)
        .collect();
    assert!(
        !extent_map_records.is_empty(),
        "export must include TransactionExtentMap changed records"
    );

    // Each TransactionExtentMap record should have a non-empty payload and
    // a valid checksum.
    for record in &extent_map_records {
        assert!(
            !record.payload.is_empty(),
            "TransactionExtentMap payload must not be empty"
        );
        assert!(
            record.checksum.get() != 0,
            "TransactionExtentMap checksum must be non-zero"
        );
    }

    // Verify that TransactionExtentMap has discriminant 8.
    assert_eq!(
        ChangedRecordObjectRole::TransactionExtentMap as u16,
        8u16,
        "TransactionExtentMap role discriminant must be 8"
    );

    // Also verify the ChangedRecordObjectRole decode round-trip.
    assert_eq!(
        ChangedRecordObjectRole::try_from(8u16),
        Ok(ChangedRecordObjectRole::TransactionExtentMap),
        "u16 round-trip to TransactionExtentMap"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn allocate_then_free_produces_distinct_changed_records() {
    set_test_key();
    let root = temp_dir("changed-record-alloc-free");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    // Allocate extent.
    fs.begin_transaction().expect("begin tx 1");
    fs.create_file("/record_test.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create record_test.bin");
    fs.write_file("/record_test.bin", 0, &[0x99u8; 8192])
        .expect("write 8 KiB");
    fs.commit_transaction().expect("commit tx 1");

    // Free extent (truncate to 0).
    fs.begin_transaction().expect("begin tx 2");
    fs.truncate_file("/record_test.bin", 0)
        .expect("truncate to 0");
    fs.commit_transaction().expect("commit tx 2");

    // Export and verify we see TransactionExtentMap entries.
    let export = fs.export_changed_records().expect("export changed records");

    assert!(
        !export.roots.is_empty(),
        "export should have at least one root"
    );

    // Collect all distinct roles across all roots.
    let all_roles: Vec<ChangedRecordObjectRole> = export
        .roots
        .iter()
        .flat_map(|root| root.records.iter().map(|r| r.role))
        .collect();

    // At least one root must contain TransactionExtentMap.
    assert!(
        all_roles.contains(&ChangedRecordObjectRole::TransactionExtentMap),
        "changed records must contain TransactionExtentMap role"
    );

    drop(fs);
    cleanup(&root);
}

// ───────────────────────────────────────────────────────────────
// Test 5: Edge cases
// ───────────────────────────────────────────────────────────────

#[test]
fn lookup_extents_on_empty_file_returns_empty() {
    set_test_key();
    let root = temp_dir("edge-empty-file");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx");
    fs.create_file("/empty.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create empty.bin");
    // Do not write any data -- no extents allocated.
    fs.commit_transaction().expect("commit tx");

    let inode_id = fs.lookup("/empty.bin").expect("lookup inode");
    let ino = inode_id.get();

    // Lookup on empty file should find no extents.
    let extents = fs.lookup_extents(ino, 0, 4096);
    assert!(extents.is_empty(), "empty file should have no extents");

    // Also check at a non-zero offset.
    let extents2 = fs.lookup_extents(ino, 1024, 4096);
    assert!(
        extents2.is_empty(),
        "empty file lookup at offset 1024 should be empty"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn lookup_extents_on_nonexistent_inode_returns_empty() {
    set_test_key();
    let root = temp_dir("edge-no-inode");

    let fs = LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");

    // Inode 99999 does not exist.
    let extents = fs.lookup_extents(99999, 0, 4096);
    assert!(
        extents.is_empty(),
        "nonexistent inode should return empty extent list"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn extent_allocator_multiple_inodes_isolation() {
    set_test_key();
    let root = temp_dir("edge-inode-isolation");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx");
    fs.create_file("/a.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create a.bin");
    fs.create_file("/b.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create b.bin");
    fs.write_file("/a.bin", 0, &[0xAAu8; 4096])
        .expect("write a.bin");
    fs.write_file("/b.bin", 0, &[0xBBu8; 8192])
        .expect("write b.bin");
    fs.commit_transaction().expect("commit tx");

    let ino_a = fs.lookup("/a.bin").expect("lookup a").get();
    let ino_b = fs.lookup("/b.bin").expect("lookup b").get();
    assert_ne!(ino_a, ino_b, "inodes should be distinct");

    let ext_a = fs.lookup_extents(ino_a, 0, 16384);
    assert_eq!(ext_a.len(), 1, "inode A: 1 extent");
    assert_eq!(ext_a[0].length, 4096);

    let ext_b = fs.lookup_extents(ino_b, 0, 16384);
    assert_eq!(ext_b.len(), 1, "inode B: 1 extent");
    assert_eq!(ext_b[0].length, 8192);

    // inode A must not see inode B's extents.
    let ext_a_full = fs.lookup_extents(ino_a, 0, 16384);
    assert_eq!(ext_a_full.len(), 1, "inode A isolation holds");

    // Verify extent allocator reports correct counts.
    let alloc = fs.extent_allocator();
    assert!(alloc.has_extents(ino_a));
    assert!(alloc.has_extents(ino_b));
    assert!(!alloc.has_extents(99999));

    drop(fs);
    cleanup(&root);
}

#[test]
fn double_truncate_to_zero_is_idempotent() {
    set_test_key();
    let root = temp_dir("edge-double-trunc");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx 1");
    fs.create_file("/shrink.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create shrink.bin");
    fs.write_file("/shrink.bin", 0, &[0x77u8; 4096])
        .expect("write 4 KiB");
    fs.commit_transaction().expect("commit tx 1");

    // First truncate: frees extents.
    fs.begin_transaction().expect("begin tx 2");
    fs.truncate_file("/shrink.bin", 0)
        .expect("truncate to 0 (1st)");
    fs.commit_transaction().expect("commit tx 2");

    // Second truncate: should be a no-op, not an error.
    fs.begin_transaction().expect("begin tx 3");
    fs.truncate_file("/shrink.bin", 0)
        .expect("truncate to 0 (2nd, should be idempotent)");
    fs.commit_transaction().expect("commit tx 3");

    let inode_id = fs.lookup("/shrink.bin").expect("lookup inode");
    let extents = fs.lookup_extents(inode_id.get(), 0, 4096);
    assert!(extents.is_empty(), "no extents after double truncate");

    // Content size should be zero.
    let data = fs.read_file("/shrink.bin").expect("read shrink.bin");
    assert!(
        data.is_empty(),
        "content should be empty after double truncate"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn truncate_shrink_partial_frees_tail_extent() {
    set_test_key();
    let root = temp_dir("edge-partial-trunc");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx");
    fs.create_file("/data.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create data.bin");
    fs.write_file("/data.bin", 0, &[0x33u8; 12288])
        .expect("write 12 KiB");
    fs.commit_transaction().expect("commit tx");

    let inode_id = fs.lookup("/data.bin").expect("lookup inode");
    let ino = inode_id.get();

    // Verify extent exists before truncate.
    let before = fs.lookup_extents(ino, 0, 16384);
    assert!(!before.is_empty(), "extent exists before partial truncate");

    // Truncate from 12288 down to 4096.
    fs.begin_transaction().expect("begin tx 2");
    fs.truncate_file("/data.bin", 4096)
        .expect("truncate to 4096");
    fs.commit_transaction().expect("commit tx 2");

    // Verify only first 4096 bytes survive.
    let data = fs.read_file("/data.bin").expect("read data.bin");
    assert_eq!(data.len(), 4096);
    assert_eq!(&data[0..4], &[0x33u8; 4]);

    // Extent lookup should show the remaining extent.
    let extents = fs.lookup_extents(ino, 0, 8192);
    assert_eq!(
        extents.len(),
        1,
        "one extent remains after partial truncate"
    );
    assert_eq!(extents[0].logical_offset, 0);
    assert_eq!(extents[0].length, 4096);

    drop(fs);
    cleanup(&root);
}

#[test]
fn write_beyond_eof_allocates_new_extent() {
    set_test_key();
    let root = temp_dir("edge-write-beyond-eof");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx");
    fs.create_file("/sparse.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create sparse.bin");
    // Write beyond EOF creates a sparse region.
    fs.write_file("/sparse.bin", 12288, &[0x44u8; 4096])
        .expect("write at 12288");
    fs.commit_transaction().expect("commit tx");

    let inode_id = fs.lookup("/sparse.bin").expect("lookup inode");
    let ino = inode_id.get();

    // Extent at offset 12288.
    let extents = fs.lookup_extents(ino, 0, 20480);
    assert_eq!(extents.len(), 1, "one extent at offset 12288");
    assert_eq!(extents[0].logical_offset, 12288);
    assert_eq!(extents[0].length, 4096);

    // Data before offset 12288 is zero-filled.
    let data = fs.read_file("/sparse.bin").expect("read sparse.bin");
    assert_eq!(data.len() as u64, 12288 + 4096);
    assert_eq!(&data[12288..12292], &[0x44u8; 4]);
    assert!(data[0..12288].iter().all(|&b| b == 0));

    drop(fs);
    cleanup(&root);
}

#[test]
fn rollback_transaction_discards_extent_allocation() {
    set_test_key();
    let root = temp_dir("edge-rollback-extent");

    let mut fs =
        LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
    fs.set_auto_commit(false);

    fs.begin_transaction().expect("begin tx");
    fs.create_file("/discarded.bin", DEFAULT_FILE_PERMISSIONS)
        .expect("create discarded.bin");
    fs.write_file("/discarded.bin", 0, &[0x55u8; 4096])
        .expect("write discarded.bin");
    fs.rollback_transaction().expect("rollback tx");

    // After rollback, file must not exist.
    assert!(
        fs.lookup("/discarded.bin").is_err(),
        "file must not exist after rollback"
    );

    drop(fs);
    cleanup(&root);
}

#[test]
fn allocate_commit_reopen_data_survives_with_changed_records() {
    set_test_key();
    let root = temp_dir("edge-reopen-records");

    // Phase 1: create file with extents and sync.
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, test_options()).expect("open filesystem");
        fs.set_auto_commit(false);

        fs.begin_transaction().expect("begin tx");
        fs.create_file("/roundtrip.bin", DEFAULT_FILE_PERMISSIONS)
            .expect("create roundtrip.bin");
        fs.write_file("/roundtrip.bin", 0, &[0x66u8; 4096])
            .expect("write");
        fs.write_file("/roundtrip.bin", 16384, &[0x77u8; 4096])
            .expect("write at 16384");
        fs.commit_transaction().expect("commit tx");
        fs.sync_all().expect("sync all");
    }

    // Phase 2: reopen and verify data content (regular filesystem read).
    {
        let mut fs =
            LocalFileSystem::open_with_options(&root, test_options()).expect("reopen filesystem");

        let data = fs.read_file("/roundtrip.bin").expect("read roundtrip.bin");
        assert_eq!(data.len() as u64, 16384 + 4096);
        assert_eq!(&data[0..4], &[0x66u8; 4]);
        assert_eq!(&data[16384..16388], &[0x77u8; 4]);

        // Verify directory listing survives.
        let listing = fs.list_dir("/").expect("list root");
        let names: Vec<String> = listing.iter().map(|e| e.name_lossy()).collect();
        assert!(names.contains(&"roundtrip.bin".to_string()));

        // Verify changed records are readable after reopen.
        let export = fs.export_changed_records().expect("export changed records");
        assert!(
            !export.roots.is_empty(),
            "export should have roots after reopen"
        );

        // Check for TransactionExtentMap records in the export.
        let ext_map_count: usize = export
            .roots
            .iter()
            .map(|root| {
                root.records
                    .iter()
                    .filter(|r| r.role == ChangedRecordObjectRole::TransactionExtentMap)
                    .count()
            })
            .sum();
        assert!(
            ext_map_count > 0,
            "reopened filesystem should have persisted TransactionExtentMap records"
        );
    }

    cleanup(&root);
}
