// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Object-I/O smoke: deterministic write/read/error checks over an
//! `InlineExtentMap` and the `LocalObjectStore` adapter.
//!
//! Gated on `feature = "fuse"`.

use crate::smoke::SmokeHarness;
use crate::trace::TraceEvent;
use tidefs_extent_map::InlineExtentMap;
use tidefs_object_io::{LocalObjectStore, ObjectIo, ObjectIoError, ObjectKey};

/// Run the full object-I/O smoke sequence and return the harness.
#[must_use]
pub fn run_object_io_smoke() -> SmokeHarness {
    let mut h = SmokeHarness::new();

    h.scenario_begin("object-io/smoke");

    let dir = tempfile::TempDir::new().expect("tempdir for object-io smoke");
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(dir.path()).expect("open local object store");
    let io = ObjectIo::with_chunk_size(4);

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "object_io.write.chunked".to_string(),
        payload: b"abcdefghij".to_vec(),
    });
    let written = io
        .write(&mut map, &mut store, 0, b"abcdefghij")
        .expect("chunked object-io write should succeed");
    h.assert_eq_ev("chunked write returns full length", written, 10usize);
    h.assert_eq_ev(
        "chunked write creates three extents",
        map.entries.len(),
        3usize,
    );

    h.record(TraceEvent::ExtentLookup {
        offset: 2,
        length: 6,
    });
    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "object_io.read.cross_extent".to_string(),
        payload: Vec::new(),
    });
    let mut cross_extent = vec![0xff; 6];
    let read = io
        .read(&map, &store, 2, &mut cross_extent)
        .expect("cross-extent object-io read should succeed");
    h.assert_eq_ev("cross-extent read returns requested length", read, 6usize);
    h.assert_eq_ev(
        "cross-extent read preserves object offsets",
        cross_extent,
        b"cdefgh".to_vec(),
    );

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "object_io.write.sparse_tail".to_string(),
        payload: b"TAIL".to_vec(),
    });
    io.write(&mut map, &mut store, 16, b"TAIL")
        .expect("sparse tail write should succeed");

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "object_io.read.sparse_hole".to_string(),
        payload: Vec::new(),
    });
    let mut sparse = vec![0xff; 20];
    let read = io
        .read(&map, &store, 0, &mut sparse)
        .expect("sparse object-io read should succeed");
    h.assert_eq_ev("sparse read returns logical file size", read, 20usize);
    h.assert_eq_ev(
        "sparse read keeps first write",
        sparse[..10].to_vec(),
        b"abcdefghij".to_vec(),
    );
    h.assert_eq_ev(
        "sparse read zero-fills gap",
        sparse[10..16].to_vec(),
        vec![0; 6],
    );
    h.assert_eq_ev(
        "sparse read returns tail write",
        sparse[16..].to_vec(),
        b"TAIL".to_vec(),
    );

    h.record(TraceEvent::FsLifecycleOp {
        inode_id: 1,
        op_name: "object_io.write.overwrite".to_string(),
        payload: b"XYZ".to_vec(),
    });
    let overwritten = io
        .write(&mut map, &mut store, 3, b"XYZ")
        .expect("overwrite should succeed");
    h.assert_eq_ev("overwrite returns replacement length", overwritten, 3usize);

    let mut overwritten_read = vec![0xff; 10];
    let read = io
        .read(&map, &store, 0, &mut overwritten_read)
        .expect("read after overwrite should succeed");
    h.assert_eq_ev(
        "overwrite read returns original prefix length",
        read,
        10usize,
    );
    h.assert_eq_ev(
        "overwrite preserves non-overlapped bytes",
        overwritten_read,
        b"abcXYZghij".to_vec(),
    );

    let missing = missing_object_read_error(&io);
    h.assert_ev("missing backing object reports MissingObject", missing);

    let mut overflow_buf = [0; 1];
    let overflow = io.read(&map, &store, u64::MAX, &mut overflow_buf);
    h.assert_ev(
        "overflowing read request reports InvalidRange",
        matches!(overflow, Err(ObjectIoError::InvalidRange)),
    );

    h.scenario_end("object-io/smoke");
    h
}

fn missing_object_read_error(io: &ObjectIo) -> bool {
    let temp = tempfile::TempDir::new().expect("tempdir for missing-object smoke");
    let mut map = InlineExtentMap::new();
    let mut store = LocalObjectStore::open(temp.path()).expect("open missing-object store");

    io.write(&mut map, &mut store, 0, b"gone")
        .expect("seed write should succeed");
    let missing_key = ObjectKey::from_bytes32(map.entries[0].checksum);
    store
        .delete(missing_key)
        .expect("deleting seeded object should succeed");

    let mut buf = [0; 4];
    matches!(
        io.read(&map, &store, 0, &mut buf),
        Err(ObjectIoError::MissingObject(key)) if key == missing_key
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_io_smoke_passes() {
        let h = run_object_io_smoke();
        for event in &h.trace {
            if let TraceEvent::Assert {
                passed,
                ref condition,
            } = event
            {
                assert!(passed, "assertion failed: {condition}");
            }
        }
    }
}
