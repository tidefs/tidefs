// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Checksum-verification integration tests for `tidefs-local-object-store`.
//!
//! Validates that `get_verified` catches content-key mismatch,
//! production integrity trailers block replay of corrupted records,
//! and corrupt headers are rejected on open.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_object_store::{LocalObjectStore, ObjectKey, StoreError, StoreOptions};

fn temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-checksum-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn cleanup(root: &PathBuf) {
    let _ = fs::remove_dir_all(root);
}

fn segment_file_path(segments_dir: &std::path::Path, segment_id: u64) -> PathBuf {
    segments_dir.join(tidefs_local_object_store::local_object_store::segment_file_name(segment_id))
}

// ---------------------------------------------------------------------------
// get_verified: correct data passes verification
// ---------------------------------------------------------------------------

/// `get_verified` on content-addressed data returns the correct payload.
#[test]
fn get_verified_succeeds_for_clean_data() {
    let root = temp_root("clean-verify");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let payload = b"data that will remain uncorrupted";
    let key = store
        .put_content_addressed(payload)
        .expect("put content-addressed");

    let verified = store
        .get_verified(key)
        .expect("get_verified")
        .expect("object should exist");
    assert_eq!(verified, payload, "verified payload must match original");

    store.sync_all().expect("sync store");
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// ContentAddressMismatch: wrong key for content
// ---------------------------------------------------------------------------

/// `get_verified` fails with `ContentAddressMismatch` when the requested
/// key does not match the BLAKE3 hash of the stored content. This guards
/// against bit-rot and key confusion (e.g. requesting a name-derived key
/// on content-addressed data).
#[test]
fn get_verified_content_address_mismatch() {
    let root = temp_root("ca-mismatch");
    let mut store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    // Store data by a name-derived (non-content) key, then verify with
    // get_verified: the stored content's BLAKE3 hash won't match the
    // name-derived key, triggering ContentAddressMismatch.
    let payload = b"data stored under a name-derived key";
    let name_key = ObjectKey::from_name(b"mismatch-test");
    store.put(name_key, payload).expect("put named");

    // get_verified must fail: the name-derived key is NOT the BLAKE3
    // hash of the payload.
    let result = store.get_verified(name_key);
    match result {
        Err(StoreError::ContentAddressMismatch { expected, actual }) => {
            assert_eq!(expected, name_key);
            assert_ne!(actual, name_key);
        }
        Ok(Some(_)) => panic!("get_verified should report mismatch"),
        Ok(None) => panic!("get_verified should find the key but reject the hash"),
        Err(other) => panic!("expected ContentAddressMismatch, got {other:?}"),
    }

    // Plain get still works (no verification)
    assert!(store.get(name_key).expect("get").is_some());

    // Content-addressed round-trip still works
    let ca_key = store.put_content_addressed(payload).expect("put ca");
    assert!(store
        .get_verified(ca_key)
        .expect("get_verified ca")
        .is_some());

    store.sync_all().expect("sync store");
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Production integrity trailer catches corruption on replay
// ---------------------------------------------------------------------------

/// Corrupt a payload byte on disk, then reopen. The BLAKE3 integrity
/// trailer covers the payload, so replay catches the mismatch as
/// `ProductionIntegrityMismatch` before any data reaches the caller.
#[test]
fn payload_corruption_is_caught_on_replay_by_integrity_trailer() {
    let root = temp_root("integrity-replay");
    let payload = b"payload protected by integrity trailer";
    let segment_path;
    let location;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store
            .put_named("protected", payload)
            .expect("put named object");
        store.sync_all().expect("sync store");
        location = store
            .location_of(ObjectKey::from_name(b"protected"))
            .expect("location exists");
        segment_path = segment_file_path(store.segments_dir(), location.segment_id);
    }

    // Corrupt a byte in the payload on disk (past the 96-byte header)
    let payload_disk_offset = location.record_offset
        + tidefs_local_object_store::local_object_store::RECORD_HEADER_LEN as u64;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .read(true)
            .open(&segment_path)
            .expect("open segment for corruption");
        f.seek(SeekFrom::Start(payload_disk_offset + 3))
            .expect("seek");
        let mut original = [0u8; 1];
        f.read_exact(&mut original).expect("read");
        f.seek(SeekFrom::Start(payload_disk_offset + 3))
            .expect("seek back");
        f.write_all(&[original[0] ^ 0xFF]).expect("corrupt");
        f.sync_all().expect("sync");
    }

    // Reopen must fail: the integrity trailer no longer matches
    let result = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast());
    match result {
        Err(StoreError::ProductionIntegrityMismatch { field, .. }) => {
            assert!(
                field == "payload digest" || field == "record digest",
                "expected payload or record digest mismatch, got field={field}"
            );
        }
        Ok(_) => panic!("reopen after corruption should fail"),
        Err(other) => panic!("expected ProductionIntegrityMismatch, got {other:?}"),
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Corrupted footer also caught on replay
// ---------------------------------------------------------------------------

/// Corrupt the record footer magic and verify reopen catches it.
#[test]
fn corrupt_footer_prevents_replay() {
    let root = temp_root("corrupt-footer");
    let segment_path;
    let location;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store.put_named("foot", b"footer test").expect("put");
        store.sync_all().expect("sync");
        location = store
            .location_of(ObjectKey::from_name(b"foot"))
            .expect("location exists");
        segment_path = segment_file_path(store.segments_dir(), location.segment_id);
    }

    // The footer sits at header_len + payload_len into the record
    let footer_offset = location.record_offset
        + tidefs_local_object_store::local_object_store::RECORD_HEADER_LEN as u64
        + location.payload_len;
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open for footer corruption");
        f.seek(SeekFrom::Start(footer_offset))
            .expect("seek to footer");
        f.write_all(b"XXXXXXXX") // was "VLOSEND2"
            .expect("corrupt footer magic");
        f.sync_all().expect("sync");
    }

    let result = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast());
    assert!(result.is_err(), "reopen with corrupted footer must fail");
    cleanup(&root);
}

// ---------------------------------------------------------------------------
// Corrupt header magic prevents reopen
// ---------------------------------------------------------------------------

#[test]
fn corrupt_header_magic_prevents_reopen() {
    let root = temp_root("corrupt-header");
    let segment_path;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        store
            .put_named("victim", b"doomed data")
            .expect("put object");
        store.sync_all().expect("sync store");
        segment_path = segment_file_path(store.segments_dir(), 0);
    }

    // Corrupt the first 8 magic bytes ("VLOSREC1")
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(&segment_path)
            .expect("open segment for header corruption");
        f.write_all(b"XXXXXXXX").expect("corrupt header magic");
        f.sync_all().expect("sync corrupted header");
    }

    let result = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast());
    match result {
        Err(StoreError::CorruptHeader { reason, .. }) => {
            assert!(
                reason.to_lowercase().contains("local object-store"),
                "corrupt header reason should describe the problem, got: {reason}"
            );
        }
        Ok(_) => panic!("reopen should have failed on corrupt header"),
        Err(other) => panic!("expected CorruptHeader, got {other:?}"),
    }

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// get_verified on nonexistent key returns Ok(None)
// ---------------------------------------------------------------------------

#[test]
fn get_verified_nonexistent_returns_none() {
    let root = temp_root("verified-nonexistent");
    let store =
        LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("open store");

    let bogus = ObjectKey::from_name(b"never-stored");
    let result = store
        .get_verified(bogus)
        .expect("get_verified on unknown key");
    assert!(result.is_none(), "nonexistent key must return None");

    cleanup(&root);
}

// ---------------------------------------------------------------------------
// get_verified survives close/reopen (clean data)
// ---------------------------------------------------------------------------

#[test]
fn checksum_verify_clean_round_trip_reopen() {
    let root = temp_root("checksum-clean-reopen");
    let payload = b"survive close and reopen with verified read";
    let key;
    {
        let mut store = LocalObjectStore::open_with_options(&root, StoreOptions::test_fast())
            .expect("open store");
        key = store
            .put_content_addressed(payload)
            .expect("put content-addressed");
        store.sync_all().expect("sync store");
    }
    {
        let store =
            LocalObjectStore::open_with_options(&root, StoreOptions::test_fast()).expect("reopen");
        let verified = store
            .get_verified(key)
            .expect("get_verified after reopen")
            .expect("object should survive reopen");
        assert_eq!(verified, payload);
    }
    cleanup(&root);
}
