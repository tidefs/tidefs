//! Smoke test: workers-io live behavior passes basic checks.
//!
//! Covers write staging, content hashing, copy_file_range planning,
//! and read cache behavior through the live worker-IO APIs.

#![cfg(feature = "fuse")]

use tidefs_posix_filesystem_adapter_workers_io::{
    staged_write_hash64, CopyFileRangePlanError, FuseCopyFileRangeRequest, NoopReadCache,
    ReadCache, WriteBuffer, WriteStagingError, COPY_FILE_RANGE_MAX_CHUNK, SEAM_FAMILY_DOC,
};
use tidefs_types_posix_filesystem_adapter_core::{
    PosixFilesystemAdapterWriteStagingRequest, SPARSE_IO_BLOCK_SIZE,
};

#[test]
fn seam_family_doc_is_not_empty() {
    assert!(!SEAM_FAMILY_DOC.is_empty());
}

#[test]
fn copy_chunk_matches_block_size() {
    assert_eq!(COPY_FILE_RANGE_MAX_CHUNK, SPARSE_IO_BLOCK_SIZE);
}

#[test]
fn write_buffer_stages_aligned_payload() {
    let mut buf = WriteBuffer::new();
    let req = PosixFilesystemAdapterWriteStagingRequest {
        unique: 1,
        inode: 100,
        fh: 10,
        offset: 0,
        length: SPARSE_IO_BLOCK_SIZE as u32,
        write_flags: 0,
        lock_owner: 0,
        _reserved: [0_u32; 2],
    };
    let data = vec![0xCC; SPARSE_IO_BLOCK_SIZE as usize];
    let staged = buf.stage(req, &data).expect("stage write");
    assert_eq!(staged.outcome.unique, 1);
    assert_eq!(staged.outcome.inode, 100);
    assert_eq!(staged.outcome.offset, 0);
    assert_eq!(staged.outcome.length, SPARSE_IO_BLOCK_SIZE as u32);
    assert!(!staged.data.is_empty());
}

#[test]
fn write_buffer_stages_zero_length_payload() {
    let mut buf = WriteBuffer::new();
    let req = PosixFilesystemAdapterWriteStagingRequest {
        unique: 2,
        inode: 200,
        fh: 20,
        offset: SPARSE_IO_BLOCK_SIZE,
        length: 0,
        write_flags: 0,
        lock_owner: 0,
        _reserved: [0_u32; 2],
    };
    let staged = buf.stage(req, &[]).expect("zero-length write");
    assert!(staged.data.is_empty());
    assert_eq!(staged.outcome.unique, 2);
    assert_eq!(staged.outcome.length, 0);
}

#[test]
fn write_buffer_rejects_misaligned_offset() {
    let mut buf = WriteBuffer::new();
    let req = PosixFilesystemAdapterWriteStagingRequest {
        unique: 3,
        inode: 300,
        fh: 30,
        offset: 3, // not block-aligned
        length: SPARSE_IO_BLOCK_SIZE as u32,
        write_flags: 0,
        lock_owner: 0,
        _reserved: [0_u32; 2],
    };
    let data = vec![0xDD; SPARSE_IO_BLOCK_SIZE as usize];
    let err = buf.stage(req, &data).unwrap_err();
    assert_eq!(err, WriteStagingError::Misaligned);
}

#[test]
fn write_buffer_rejects_length_mismatch() {
    let mut buf = WriteBuffer::new();
    let req = PosixFilesystemAdapterWriteStagingRequest {
        unique: 4,
        inode: 400,
        fh: 40,
        offset: 0,
        length: 16,
        write_flags: 0,
        lock_owner: 0,
        _reserved: [0_u32; 2],
    };
    let err = buf.stage(req, b"too-short").unwrap_err();
    assert_eq!(err, WriteStagingError::LengthMismatch);
}

#[test]
fn staged_write_hash64_is_deterministic() {
    let h1 = staged_write_hash64(b"hello world");
    let h2 = staged_write_hash64(b"hello world");
    assert_eq!(h1, h2);
}

#[test]
fn staged_write_hash64_differs_for_different_input() {
    let h1 = staged_write_hash64(b"hello");
    let h2 = staged_write_hash64(b"world");
    assert_ne!(h1, h2);
}

#[test]
fn copy_file_range_request_plan_valid() {
    let req = FuseCopyFileRangeRequest::new(100, 10, 20, 0, 30, 40, 1024, 4096, 0);
    let plan = req.plan().expect("valid copy request");
    assert_eq!(plan.unique, 100);
    assert_eq!(plan.ino_in, 10);
    assert_eq!(plan.ino_out, 30);
    assert_eq!(plan.len, 4096);
}

#[test]
fn copy_file_range_rejects_negative_source_offset() {
    let req = FuseCopyFileRangeRequest::new(1, 2, 3, -1, 4, 5, 0, 4096, 0);
    assert_eq!(
        req.plan().unwrap_err(),
        CopyFileRangePlanError::NegativeOffset
    );
}

#[test]
fn copy_file_range_rejects_negative_dest_offset() {
    let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, -1, 4096, 0);
    assert_eq!(
        req.plan().unwrap_err(),
        CopyFileRangePlanError::NegativeOffset
    );
}

#[test]
fn copy_file_range_rejects_nonzero_flags() {
    let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, 0, 4096, 1);
    assert_eq!(
        req.plan().unwrap_err(),
        CopyFileRangePlanError::UnsupportedFlags
    );
}

#[test]
fn copy_file_range_rejects_overflowing_range() {
    let req = FuseCopyFileRangeRequest::new(1, 2, 3, 0, 4, 5, 0, u64::MAX, 0);
    assert_eq!(
        req.plan().unwrap_err(),
        CopyFileRangePlanError::InvalidRange
    );
}

#[test]
fn copy_file_range_plan_error_to_errno() {
    assert_eq!(
        CopyFileRangePlanError::NegativeOffset.to_errno(),
        22 // EINVAL
    );
    assert_eq!(
        CopyFileRangePlanError::UnsupportedFlags.to_errno(),
        22 // EINVAL
    );
    assert_eq!(
        CopyFileRangePlanError::InvalidRange.to_errno(),
        22 // EINVAL
    );
}

#[test]
fn read_cache_noop_is_noop() {
    let cache = NoopReadCache;
    assert!(cache.lookup(1, 0, 256).is_none());
    let mut cache = NoopReadCache;
    cache.insert(1, 0, b"irrelevant");
    assert!(cache.lookup(1, 0, 8).is_none());
}

#[test]
fn read_cache_trait_object_accepted() {
    fn consume(_c: &dyn ReadCache) {}
    consume(&NoopReadCache);
}
