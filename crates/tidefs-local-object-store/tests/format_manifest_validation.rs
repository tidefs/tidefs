// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Format manifest lifecycle validation — Tier 3 userspace runtime validation.
//!
//! Validates that the [`LocalObjectStoreFormatManifest`] is written on store
//! creation, survives reopen unchanged, and that an incompatible manifest
//! triggers the rejection gate (StoreError::FormatIncompatible) on open.
//!
//! These tests exercise the full store create/open/reopen path and
//! constitute Tier 3 mounted userspace/storage runtime validation for
//! NEXT-STOR-035.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{format_manifest, LocalObjectStore, StoreError, StoreOptions};

type ManifestMutation = Box<dyn Fn(&mut format_manifest::LocalObjectStoreFormatManifest)>;

// ── Fixture helpers ────────────────────────────────────────────────────────

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-fmt-manifest-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn fast_opts() -> StoreOptions {
    StoreOptions {
        verify_read_checksums: false,
        max_segment_bytes: 4096,
        sync_on_write: false,
        repair_torn_tail: true,
        segment_rotation_interval_secs: u64::MAX,
        segment_rotation_write_limit: 0,
        reclaim_enabled: false,
        write_throttle_enabled: false,
        ..StoreOptions::test_fast()
    }
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

/// Well-known file name the store writes its manifest to.
const FORMAT_MANIFEST_FILE_NAME: &str = "format_manifest";

// ── Tests ───────────────────────────────────────────────────────────────────

#[test]
fn manifest_written_on_store_create() {
    let root = temp_root("create");
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
    }
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
    assert!(
        manifest_path.exists(),
        "format manifest must exist after store creation at {}",
        manifest_path.display()
    );
    let bytes = fs::read(&manifest_path).expect("read manifest");
    let stored = format_manifest::LocalObjectStoreFormatManifest::from_bytes(&bytes)
        .expect("decode manifest");
    assert_eq!(
        stored,
        format_manifest::CURRENT_FORMAT_MANIFEST,
        "stored manifest must match CURRENT_FORMAT_MANIFEST"
    );
    cleanup(&root);
}

#[test]
fn manifest_survives_reopen() {
    let root = temp_root("reopen");
    {
        let mut store =
            LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
        store.put_named(b"hello", b"world").expect("put");
        store.sync_all().expect("sync");
    }
    // Reopen — manifest must still be valid.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("reopen store");
    }
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
    let bytes = fs::read(&manifest_path).expect("read manifest");
    let stored = format_manifest::LocalObjectStoreFormatManifest::from_bytes(&bytes)
        .expect("decode manifest");
    assert_eq!(
        stored,
        format_manifest::CURRENT_FORMAT_MANIFEST,
        "manifest must survive reopen unchanged"
    );
    cleanup(&root);
}

#[test]
fn incompatible_manifest_rejected_on_open() {
    let root = temp_root("reject");
    // Create a store normally.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
    }
    // Corrupt the manifest: set a future record_format_version_max.
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
    let mut stored = {
        let bytes = fs::read(&manifest_path).expect("read manifest");
        format_manifest::LocalObjectStoreFormatManifest::from_bytes(&bytes)
            .expect("decode manifest")
    };
    stored.record_format_version_max = 99; // future version
    fs::write(&manifest_path, stored.to_bytes()).expect("write corrupted manifest");

    // Reopen must fail with FormatIncompatible.
    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    match result {
        Err(StoreError::FormatIncompatible { field, .. }) => {
            assert_eq!(
                field, "record_format_version_max",
                "rejection must name the incompatible field"
            );
        }
        other => panic!("expected FormatIncompatible, got {other:?}"),
    }
    cleanup(&root);
}

#[test]
fn incompatible_manifest_rejected_then_restored() {
    let root = temp_root("restore");
    // Create store.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
    }
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
    let original_bytes = fs::read(&manifest_path).expect("read original manifest");

    // Corrupt and verify rejection.
    let mut corrupted =
        format_manifest::LocalObjectStoreFormatManifest::from_bytes(&original_bytes)
            .expect("decode");
    corrupted.record_format_version_max = 99;
    fs::write(&manifest_path, corrupted.to_bytes()).expect("write corrupted");

    let result = LocalObjectStore::open_with_options(&root, fast_opts());
    assert!(
        matches!(result, Err(StoreError::FormatIncompatible { .. })),
        "corrupted manifest must be rejected"
    );

    // Restore original manifest and verify reopen succeeds.
    fs::write(&manifest_path, &original_bytes).expect("restore original");
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts())
            .expect("reopen after manifest restore");
    }
    cleanup(&root);
}

#[test]
fn manifest_missing_is_tolerated() {
    let root = temp_root("missing");
    // Create store normally first.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
    }
    // Remove the manifest file.
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);
    fs::remove_file(&manifest_path).expect("remove manifest");

    // Reopen must still succeed — missing manifest is tolerated.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts())
            .expect("reopen without manifest");
    }
    cleanup(&root);
}

#[test]
fn each_incompatible_field_rejected() {
    let root = temp_root("fields");
    // Create a store and get its manifest.
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts()).expect("create store");
    }
    let manifest_path = root.join(FORMAT_MANIFEST_FILE_NAME);

    // Test each independently-incompatible field.
    let incompatible_cases: Vec<(&str, ManifestMutation)> = vec![
        (
            "record_format_version_min",
            Box::new(|m| {
                m.record_format_version_min =
                    format_manifest::CURRENT_FORMAT_MANIFEST.record_format_version_max + 1;
            }),
        ),
        (
            "index_base_format_version",
            Box::new(|m| {
                m.index_base_format_version = 99;
            }),
        ),
        (
            "spacemap_base_format_version",
            Box::new(|m| {
                m.spacemap_base_format_version = 99;
            }),
        ),
        (
            "suspect_log_format_version_min",
            Box::new(|m| {
                m.suspect_log_format_version_min =
                    format_manifest::CURRENT_FORMAT_MANIFEST.suspect_log_format_version_max + 1;
            }),
        ),
        (
            "integrity_trailer_digest_suite_id",
            Box::new(|m| {
                m.integrity_trailer_digest_suite_id = 99;
            }),
        ),
    ];

    let original_bytes = fs::read(&manifest_path).expect("read original");

    for (expected_field, corrupt) in &incompatible_cases {
        // Reset to original.
        fs::write(&manifest_path, &original_bytes).expect("restore original");
        let mut m = format_manifest::LocalObjectStoreFormatManifest::from_bytes(
            &fs::read(&manifest_path).expect("read"),
        )
        .expect("decode");
        corrupt(&mut m);
        fs::write(&manifest_path, m.to_bytes()).expect("write corrupted");

        let result = LocalObjectStore::open_with_options(&root, fast_opts());
        match result {
            Err(StoreError::FormatIncompatible { field, .. }) => {
                assert_eq!(
                    field, *expected_field,
                    "incompatible field must be '{expected_field}'"
                );
            }
            other => panic!("expected FormatIncompatible for {expected_field}, got {other:?}"),
        }
    }

    // Restore and verify final reopen succeeds.
    fs::write(&manifest_path, &original_bytes).expect("restore original");
    {
        let _store = LocalObjectStore::open_with_options(&root, fast_opts())
            .expect("reopen after all corruption tests");
    }
    cleanup(&root);
}
