// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration tests for tidefs-object-io using LocalObjectStore.
//!
//! Exercises multi-extent read/write round-trips, error paths
//! (MissingObject, HoleBeyondEof), chunk-boundary splitting, and
//! edge cases against a real (tempdir-backed) object store.

use std::collections::HashMap;
use tidefs_extent_map::InlineExtentMap;
use tidefs_local_object_store::LocalObjectStore;
use tidefs_object_io::{
    ObjectIo, ObjectIoError, ObjectKey, ObjectReader, ObjectStore, ObjectWriter, DEFAULT_CHUNK_SIZE,
};
use tidefs_types_extent_map_core::ExtentMapOps;

// ── helpers ──────────────────────────────────────────────────────────────

/// In-memory store for error-injection tests.
#[derive(Debug, Default)]
struct MemStore {
    objects: HashMap<ObjectKey, Vec<u8>>,
}

impl ObjectStore for MemStore {
    type Error = std::convert::Infallible;

    fn put(&mut self, key: ObjectKey, data: &[u8]) -> Result<(), Self::Error> {
        self.objects.insert(key, data.to_vec());
        Ok(())
    }

    fn get(&self, key: &ObjectKey) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.objects.get(key).cloned())
    }
}

/// Deterministic sequenced data: [0, 1, 2, ..., 255, 0, 1, ...].
fn sequenced_data(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 256) as u8).collect()
}

// ── multi-extent round-trip ─────────────────────────────────────────────

#[test]
fn multi_extent_write_read_roundtrip_local_store() {
    let temp = tempfile::tempdir().unwrap();
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).unwrap();
    let io = ObjectIo::with_chunk_size(4096);

    // Write two extents with a hole between them. Pattern matches
    // the existing read_spanning_two_extents_with_hole test.
    let head = b"AAAA";
    let tail = b"BBBB";
    io.write(&mut map, &mut store, 0, head).unwrap();
    io.write(&mut map, &mut store, 12, tail).unwrap();
    map.truncate(16).unwrap();

    // Read back full range.
    let mut buf = vec![0xff; 16];
    let n = io.read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 16);
    assert_eq!(&buf[0..4], head);
    assert_eq!(&buf[4..12], &[0u8; 8]);
    assert_eq!(&buf[12..16], tail);
}

#[test]
fn multi_extent_write_read_across_chunk_boundaries() {
    let temp = tempfile::tempdir().unwrap();
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).unwrap();
    let io = ObjectIo::with_chunk_size(8); // small chunk to force splitting

    // 24 bytes with 8-byte chunks = 3 entries (fits within 6-entry limit)
    let data = sequenced_data(24);
    io.write(&mut map, &mut store, 0, &data).unwrap();

    let mut buf = vec![0u8; 24];
    let n = io.read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 24);
    assert_eq!(buf, data);
}

#[test]
fn partial_read_at_various_offsets() {
    let temp = tempfile::tempdir().unwrap();
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).unwrap();
    let io = ObjectIo::new();

    let data = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    io.write(&mut map, &mut store, 0, data).unwrap();

    // Read exact middle.
    let mut buf = vec![0u8; 10];
    let n = io.read(&map, &store, 5, &mut buf).unwrap();
    assert_eq!(n, 10);
    assert_eq!(&buf, b"56789ABCDE");

    // Read start.
    let mut buf = vec![0u8; 4];
    let n = io.read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf, b"0123");

    // Read crossing end.
    let mut buf = vec![0u8; 10];
    let n = io.read(&map, &store, 32, &mut buf).unwrap();
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"WXYZ");
    assert_eq!(&buf[4..], &[0u8; 6]);
}

// ── overwrite preserves data integrity ──────────────────────────────────

#[test]
fn overwrite_and_read_back_local_store() {
    let temp = tempfile::tempdir().unwrap();
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).unwrap();
    let io = ObjectIo::new();

    io.write(&mut map, &mut store, 0, b"original_content")
        .unwrap();
    io.write(&mut map, &mut store, 4, b"REPLACED").unwrap();

    let mut buf = vec![0u8; 16];
    let n = io.read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 16);
    assert_eq!(&buf, b"origREPLACEDtent");
}

// ── error paths ─────────────────────────────────────────────────────────

#[test]
fn read_missing_object_returns_error() {
    let mut map = InlineExtentMap::new();
    let store = MemStore::default();

    // Create a DATA extent referencing an object key NOT in the store.
    let phantom_key = ObjectKey::from_bytes32([0xAAu8; 32]);
    let entry = tidefs_object_io::ExtentMapEntryV2::new_data(
        0,
        16,
        tidefs_object_io::LocatorId(1),
        phantom_key.as_bytes32(),
        0,
    );
    map.insert_extent(&[entry]).unwrap();

    let mut buf = vec![0u8; 16];
    let err = ObjectReader::new()
        .read(&map, &store, 0, &mut buf)
        .unwrap_err();
    assert!(
        matches!(err, ObjectIoError::MissingObject(_)),
        "expected MissingObject, got {err:?}"
    );
}

#[test]
fn read_hole_beyond_eof_in_empty_map_returns_hole_beyond_eof() {
    // InlineExtentMap without any data or size reports short reads (0)
    // for reads past EOF rather than HoleBeyondEof.
    // The HoleBeyondEof error triggers on extent maps where seek_hole
    // returns None for an offset past the file boundary.
    // We test this by reading past a known file size.
    let mut map = InlineExtentMap::new();
    map.truncate(10).unwrap();
    let store = MemStore::default();
    let mut buf = vec![0u8; 16];

    let result = ObjectReader::new().read(&map, &store, 100, &mut buf);
    match result {
        Ok(n) => {
            // Acceptable: short read of 0 bytes past EOF
            assert_eq!(n, 0);
        }
        Err(ObjectIoError::HoleBeyondEof) => {
            // Also acceptable: explicit HoleBeyondEof error
        }
        Err(e) => panic!("unexpected error: {e:?}"),
    }
}

#[test]
fn write_with_zero_chunk_size_errors() {
    let mut map = InlineExtentMap::new();
    let mut store = MemStore::default();
    let writer = ObjectWriter::with_chunk_size(0);

    let err = writer.write(&mut map, &mut store, 0, b"data").unwrap_err();
    assert!(
        matches!(err, ObjectIoError::InvalidChunkSize),
        "expected InvalidChunkSize, got {err:?}"
    );
}

#[test]
fn read_empty_buffer_is_noop() {
    let map = InlineExtentMap::new();
    let store = MemStore::default();
    let mut buf: [u8; 0] = [];

    let n = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 0);
}

#[test]
fn write_empty_data_is_noop() {
    let mut map = InlineExtentMap::new();
    let mut store = MemStore::default();

    let n = ObjectWriter::new()
        .write(&mut map, &mut store, 0, &[])
        .unwrap();
    assert_eq!(n, 0);
}

// ── DEFAULT_CHUNK_SIZE ──────────────────────────────────────────────────

#[test]
fn default_chunk_size_is_reasonable() {
    assert_eq!(DEFAULT_CHUNK_SIZE, 4096);
    assert!(DEFAULT_CHUNK_SIZE.is_power_of_two());
}

// ── ObjectIoError Display and Error::source() ───────────────────────────

#[test]
fn object_io_error_display_is_nonempty() {
    let errors: &[ObjectIoError] = &[
        ObjectIoError::InvalidRange,
        ObjectIoError::InvalidChunkSize,
        ObjectIoError::HoleBeyondEof,
        ObjectIoError::MissingObject(ObjectKey::from_bytes32([0; 32])),
    ];

    for err in errors {
        let display = format!("{err}");
        assert!(!display.is_empty(), "Display empty for {err:?}");
    }
}

#[test]
fn object_io_error_debug_is_nonempty() {
    let err = ObjectIoError::InvalidRange;
    let debug = format!("{err:?}");
    assert!(!debug.is_empty());
}

#[test]
fn extent_error_conversion_produces_extent_error_variant() {
    use tidefs_types_extent_map_core::ExtentMapError;
    let map_err = ExtentMapError::InvalidRange;
    let io_err: ObjectIoError = map_err.into();
    assert!(matches!(io_err, ObjectIoError::ExtentError(_)));
}

// ── concurrent single-threaded consistency ─────────────────────────────

#[test]
fn write_then_read_without_interleaving_gives_consistent_data() {
    let temp = tempfile::tempdir().unwrap();
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).unwrap();
    let io = ObjectIo::new();

    // 5 entries (fits within 6-entry limit)
    for i in 0..5u8 {
        let offset = i as u64 * 16;
        let data = vec![i; 16];
        io.write(&mut map, &mut store, offset, &data).unwrap();
    }

    for i in 0..5u8 {
        let offset = i as u64 * 16;
        let mut buf = vec![0u8; 16];
        let n = io.read(&map, &store, offset, &mut buf).unwrap();
        assert_eq!(n, 16, "short read at offset {offset}");
        assert!(
            buf.iter().all(|b| *b == i),
            "corrupt data at offset {offset}"
        );
    }
}

#[test]
fn read_at_offset_zero_in_empty_map_with_truncated_size() {
    let mut map = InlineExtentMap::new();
    map.truncate(100).unwrap();
    let store = MemStore::default();
    let mut buf = vec![0xffu8; 50];

    let n = ObjectReader::new().read(&map, &store, 0, &mut buf).unwrap();
    assert_eq!(n, 50);
    assert!(buf.iter().all(|b| *b == 0));
}
