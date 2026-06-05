// fallocate_tests.rs -- unit tests for fallocate modes and sparse-file
// semantics on LocalFileSystem.
//
// Covers punch_hole, zero_range, fallocate_file (default + KEEP_SIZE),
// sparse readback, cross-page operations, and edge cases.

#[cfg(test)]
use super::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn ft_temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-fallocate-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn ft_options() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 128 * 1024,
        sync_on_write: false,
        repair_torn_tail: true,
        mirror_path: None,
        replica_paths: Vec::new(),
        segment_rotation_interval_secs: 0,
        segment_rotation_write_limit: 0,
        fault_injection_config: None,
        background_scrub_interval_secs: 0,
        segment_count: 65536,
        reclaim_enabled: true,

        verify_read_checksums: false,
        durability_layout: None,
        write_throttle_enabled: false,
    }
}

fn ft_cleanup(root: &std::path::Path) {
    let _ = fs::remove_dir_all(root);
}

// ===========================================================
// Group 1: Punch hole (complementing tests.rs coverage)
// ===========================================================

#[test]
fn punch_hole_partial_chunk_boundaries_preserves_partial_chunk_data() {
    let root = ft_temp_root("punch-partial");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 223) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let hole_offset = (chunk / 2) as u64;
    let hole_length = chunk as u64;
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("punch hole");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), total, "file size unchanged");

    assert_eq!(
        &read[..hole_offset as usize],
        &bytes[..hole_offset as usize],
        "bytes before hole preserved"
    );

    let hole_end = hole_offset as usize + hole_length as usize;
    assert!(
        read[hole_offset as usize..hole_end].iter().all(|&b| b == 0),
        "hole region is zeros"
    );
    assert_eq!(
        &read[hole_end..],
        &bytes[hole_end..],
        "bytes after hole preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn punch_hole_twice_same_region_is_idempotent() {
    let root = ft_temp_root("punch-twice");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 191) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let hole_offset = chunk as u64;
    let hole_length = chunk as u64;

    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("first punch");
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("second punch (idempotent)");

    let read = fs.read_file("/file.bin").expect("read after double punch");
    assert_eq!(read.len(), total, "file size unchanged");
    assert_eq!(
        &read[..hole_offset as usize],
        &bytes[..hole_offset as usize]
    );
    let hole_end = hole_offset as usize + hole_length as usize;
    assert!(read[hole_offset as usize..hole_end].iter().all(|&b| b == 0));
    assert_eq!(&read[hole_end..], &bytes[hole_end..]);

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn punch_hole_single_byte_zeros_one_byte() {
    let root = ft_temp_root("punch-byte");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..64).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    fs.punch_hole("/file.bin", 31, 1).expect("punch one byte");

    let read = fs.read_file("/file.bin").expect("read after punch");
    assert_eq!(read.len(), 64, "file size unchanged");
    assert_eq!(read[31], 0, "byte 31 is zero");
    assert_eq!(&read[..31], &bytes[..31], "bytes before preserved");
    assert_eq!(&read[32..], &bytes[32..], "bytes after preserved");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 2: Zero range (new function under test)
// ===========================================================

#[test]
fn zero_range_middle_returns_zeros_and_preserves_surrounding_data() {
    let root = ft_temp_root("zero-middle");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let zero_offset = chunk as u64;
    let zero_length = chunk as u64;
    let record = fs
        .zero_range("/file.bin", zero_offset, zero_length)
        .expect("zero middle range");
    assert_eq!(record.size, total as u64, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read after zero");
    assert_eq!(read.len(), total, "file size unchanged");
    assert_eq!(
        &read[..zero_offset as usize],
        &bytes[..zero_offset as usize],
        "bytes before zero range preserved"
    );

    let zero_end = zero_offset as usize + zero_length as usize;
    assert!(
        read[zero_offset as usize..zero_end].iter().all(|&b| b == 0),
        "zero range is zeros"
    );
    assert_eq!(
        &read[zero_end..],
        &bytes[zero_end..],
        "bytes after zero range preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_existing_data_does_not_charge_capacity_again() {
    let root = ft_temp_root("zero-existing-capacity");
    let policy = LocalStorageAllocatorPolicy::new(
        content_chunk_size() as u64 * 2,
        DEFAULT_LOCAL_FILESYSTEM_INODE_CAPACITY,
    );
    let mut fs =
        LocalFileSystem::open_with_allocator_policy(&root, ft_options(), policy).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let bytes = vec![0x7b; chunk];
    fs.write_file("/file.bin", 0, &bytes)
        .expect("fill one-chunk filesystem");
    fs.flush_all_write_buffers()
        .expect("flush initial one-chunk write");
    let before = fs.statfs().expect("statfs before zero range");
    assert_eq!(
        before.blocks,
        policy.content_capacity_bytes / u64::from(before.frsize)
    );
    assert!(before.bfree < before.blocks);
    assert_eq!(before.bavail, before.bfree);

    fs.zero_range("/file.bin", 0, chunk as u64)
        .expect("zero existing allocated data");
    let after = fs.statfs().expect("statfs after zero range");
    assert_eq!(after.blocks, before.blocks);
    assert_eq!(after.bfree, before.bfree);
    assert_eq!(after.bavail, before.bavail);

    let read = fs.read_file("/file.bin").expect("read after zero");
    assert_eq!(read.len(), chunk);
    assert!(read.iter().all(|&b| b == 0), "range is zeroed");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_start_returns_zeros_and_preserves_tail() {
    let root = ft_temp_root("zero-start");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 163) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let zero_length = chunk as u64;
    fs.zero_range("/file.bin", 0, zero_length)
        .expect("zero at start");

    let read = fs.read_file("/file.bin").expect("read after zero");
    assert_eq!(read.len(), total, "file size unchanged");
    assert!(
        read[..zero_length as usize].iter().all(|&b| b == 0),
        "start range is zeros"
    );
    assert_eq!(
        &read[zero_length as usize..],
        &bytes[zero_length as usize..],
        "bytes after zero range preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_end_returns_zeros_and_preserves_head() {
    let root = ft_temp_root("zero-end");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 173) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let zero_offset = (chunk * 2) as u64;
    let zero_length = chunk as u64;
    fs.zero_range("/file.bin", zero_offset, zero_length)
        .expect("zero at end");

    let read = fs.read_file("/file.bin").expect("read after zero");
    assert_eq!(read.len(), total, "file size unchanged");
    assert_eq!(
        &read[..zero_offset as usize],
        &bytes[..zero_offset as usize],
        "bytes before zero range preserved"
    );
    assert!(
        read[zero_offset as usize..].iter().all(|&b| b == 0),
        "end range is zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_past_eof_is_noop() {
    let root = ft_temp_root("zero-past-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello zero past eof";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let record = fs
        .zero_range("/file.bin", bytes.len() as u64 + 100, 4096)
        .expect("zero past EOF returns Ok");
    assert_eq!(record.size, bytes.len() as u64, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read after no-op zero");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_zero_length_is_noop() {
    let root = ft_temp_root("zero-zero-len");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"some data for zero test";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let record = fs
        .zero_range("/file.bin", 5, 0)
        .expect("zero-length zero_range is Ok");
    assert_eq!(record.size, bytes.len() as u64, "size unchanged");

    let read = fs
        .read_file("/file.bin")
        .expect("read after zero-length zero_range");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_on_directory_is_rejected() {
    let root = ft_temp_root("zero-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");

    let err = fs
        .zero_range("/docs", 0, 4096)
        .expect_err("zero_range on dir should error");
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "expected IsDirectory, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn zero_range_beyond_file_bounds_clamps_to_eof() {
    let root = ft_temp_root("zero-beyond-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    fs.zero_range("/file.bin", 3, 100)
        .expect("zero beyond EOF clamped");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), bytes.len());
    assert_eq!(&read[..3], &bytes[..3], "bytes before zero preserved");
    assert_eq!(read[3], 0, "byte 3 zeroed");
    assert_eq!(read[4], 0, "byte 4 zeroed (last byte clamped)");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_overwrite_then_readback_matches() {
    let root = ft_temp_root("zero-overwrite");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    fs.zero_range("/file.bin", 64, 64).expect("zero range");
    let new_bytes: Vec<u8> = (0..64).map(|i| (200u8).wrapping_add(i)).collect();
    fs.write_file("/file.bin", 64, &new_bytes)
        .expect("write over zeros");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read[..64], &bytes[..64], "head preserved");
    assert_eq!(&read[64..128], &new_bytes, "new data written over zeros");
    assert_eq!(&read[128..], &bytes[128..], "tail preserved");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 3: KEEP_SIZE allocate
// ===========================================================

#[test]
fn fallocate_keep_size_within_existing_file_is_noop() {
    let root = ft_temp_root("alloc-keep-size");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"keep size test data";
    fs.write_file("/file.bin", 0, bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let record = fs
        .fallocate_file("/file.bin", 5, 3)
        .expect("fallocate within bounds");
    assert_eq!(record.size, original_size, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn fallocate_keep_size_beyond_eof_extends_file() {
    let root = ft_temp_root("alloc-keep-beyond");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello world";
    fs.write_file("/file.bin", 0, bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let extend_by = (content_chunk_size() * 2) as u64;
    let record = fs
        .fallocate_file("/file.bin", original_size, extend_by)
        .expect("fallocate beyond EOF");
    assert_eq!(
        record.size,
        original_size + extend_by,
        "file size grows by fallocate amount"
    );

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), record.size as usize);
    assert_eq!(&read[..bytes.len()], bytes, "original data preserved");
    assert!(
        read[bytes.len()..].iter().all(|&b| b == 0),
        "fallocated region reads as zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 4: Default allocate (fallocate_file extends file)
// ===========================================================

#[test]
fn fallocate_default_zero_offset_extends_file_and_reads_zeros() {
    let root = ft_temp_root("alloc-default");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let alloc_len = (content_chunk_size() * 2) as u64;
    let record = fs
        .fallocate_file("/file.bin", 0, alloc_len)
        .expect("fallocate");
    assert_eq!(record.size, alloc_len, "file size set to fallocate length");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), alloc_len as usize);
    assert!(
        read.iter().all(|&b| b == 0),
        "fallocated file reads as all zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn fallocate_default_extends_existing_file() {
    let root = ft_temp_root("alloc-extend");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let initial: Vec<u8> = (0..64).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &initial)
        .expect("write initial");

    let extend_by = content_chunk_size() as u64;
    let record = fs
        .fallocate_file("/file.bin", initial.len() as u64, extend_by)
        .expect("fallocate extend");
    assert_eq!(
        record.size,
        initial.len() as u64 + extend_by,
        "size extended"
    );

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read[..initial.len()], &initial, "original data preserved");
    assert!(
        read[initial.len()..].iter().all(|&b| b == 0),
        "extended region reads zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn fallocate_default_within_existing_file_is_noop() {
    let root = ft_temp_root("alloc-within");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..512).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let record = fs
        .fallocate_file("/file.bin", 10, 20)
        .expect("fallocate within bounds");
    assert_eq!(record.size, original_size, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read, &bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 5: Sparse file readback
// ===========================================================

#[test]
fn sparse_file_writes_at_disjoint_offsets_reads_holes_as_zeros() {
    let root = ft_temp_root("sparse-readback");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/sparse.bin", 0o644).expect("create file");

    let first: Vec<u8> = (0..64).map(|i| i as u8).collect();
    let second: Vec<u8> = (100..164).map(|i| i as u8).collect();
    let third: Vec<u8> = (200..264).map(|i| i as u8).collect();

    fs.write_file("/sparse.bin", 0, &first)
        .expect("write first");
    fs.write_file("/sparse.bin", 100, &second)
        .expect("write second");
    fs.write_file("/sparse.bin", 200, &third)
        .expect("write third");

    let read = fs.read_file("/sparse.bin").expect("read sparse file");
    let expected_size = 264;
    assert_eq!(
        read.len(),
        expected_size,
        "file size reflects last write end"
    );

    assert_eq!(&read[..64], &first, "first chunk intact");
    assert!(
        read[64..100].iter().all(|&b| b == 0),
        "hole between first and second reads zeros"
    );
    assert_eq!(&read[100..164], &second, "second chunk intact");
    assert!(
        read[164..200].iter().all(|&b| b == 0),
        "hole between second and third reads zeros"
    );
    assert_eq!(&read[200..264], &third, "third chunk intact");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn sparse_file_hole_at_start_reads_zeros() {
    let root = ft_temp_root("sparse-start");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/sparse.bin", 0o644).expect("create file");

    let data: Vec<u8> = (0..128).map(|i| i as u8).collect();
    fs.write_file("/sparse.bin", 64, &data)
        .expect("write at offset 64");

    let read = fs.read_file("/sparse.bin").expect("read");
    assert_eq!(read.len(), 64 + 128);
    assert!(
        read[..64].iter().all(|&b| b == 0),
        "hole at start reads zeros"
    );
    assert_eq!(&read[64..], &data, "data after hole intact");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn sparse_file_range_before_buffered_write_reads_zero_gap() {
    let root = ft_temp_root("sparse-range-before-write");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/sparse.bin", 0o644).expect("create file");

    let data: Vec<u8> = (0..128).map(|i| i as u8).collect();
    fs.write_file("/sparse.bin", 64, &data)
        .expect("write at offset 64");

    let gap = fs
        .read_file_range("/sparse.bin", 0, 64)
        .expect("read sparse leading gap");
    assert_eq!(gap.len(), 64);
    assert!(gap.iter().all(|&b| b == 0), "leading gap reads zeros");

    let crossing = fs
        .read_file_range("/sparse.bin", 32, 64)
        .expect("read sparse gap crossing data");
    assert_eq!(crossing.len(), 64);
    assert!(crossing[..32].iter().all(|&b| b == 0));
    assert_eq!(&crossing[32..], &data[..32]);

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn sparse_file_reopen_preserves_hole_structure() {
    let root = ft_temp_root("sparse-reopen");
    let chunk = content_chunk_size() as usize;

    {
        let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
        fs.create_file("/sparse.bin", 0o644).expect("create file");

        let first: Vec<u8> = (0..chunk).map(|i| (i % 211) as u8).collect();
        fs.write_file("/sparse.bin", 0, &first)
            .expect("write chunk 0");

        let third: Vec<u8> = (0..chunk).map(|i| (i % 223) as u8).collect();
        fs.write_file("/sparse.bin", (chunk * 2) as u64, &third)
            .expect("write chunk 2");

        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("reopen fs");
    let read = fs.read_file("/sparse.bin").expect("read after reopen");
    assert_eq!(read.len(), chunk * 3);

    let expected_first: Vec<u8> = (0..chunk).map(|i| (i % 211) as u8).collect();
    assert_eq!(&read[..chunk], &expected_first);
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "hole preserved across reopen"
    );
    let expected_third: Vec<u8> = (0..chunk).map(|i| (i % 223) as u8).collect();
    assert_eq!(&read[chunk * 2..], &expected_third);

    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 6: Cross-page / cross-chunk partial operations
// ===========================================================

#[test]
fn punch_hole_cross_chunk_boundary_zeros_both_sides() {
    let root = ft_temp_root("punch-cross");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 197) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let hole_offset = (chunk - 100) as u64;
    let hole_length = 200;
    fs.punch_hole("/file.bin", hole_offset, hole_length)
        .expect("punch across boundary");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(
        &read[..hole_offset as usize],
        &bytes[..hole_offset as usize]
    );
    let hole_end = hole_offset as usize + hole_length as usize;
    assert!(read[hole_offset as usize..hole_end].iter().all(|&b| b == 0));
    assert_eq!(&read[hole_end..], &bytes[hole_end..]);

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn zero_range_cross_chunk_boundary_zeros_both_sides() {
    let root = ft_temp_root("zero-cross");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 211) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let zero_offset = (chunk - 50) as u64;
    let zero_length = 100;
    fs.zero_range("/file.bin", zero_offset, zero_length)
        .expect("zero across boundary");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(
        &read[..zero_offset as usize],
        &bytes[..zero_offset as usize]
    );
    let zero_end = zero_offset as usize + zero_length as usize;
    assert!(read[zero_offset as usize..zero_end].iter().all(|&b| b == 0));
    assert_eq!(&read[zero_end..], &bytes[zero_end..]);

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn punch_hole_unaligned_start_and_end_preserves_edge_bytes() {
    let root = ft_temp_root("punch-unalign");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let total = 64;
    let bytes: Vec<u8> = (0..total).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    fs.punch_hole("/file.bin", 7, 47).expect("punch unaligned");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), total);
    assert_eq!(&read[..7], &bytes[..7], "bytes before hole preserved");
    assert!(read[7..54].iter().all(|&b| b == 0), "hole is zeros");
    assert_eq!(&read[54..], &bytes[54..], "bytes after hole preserved");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 7: Edge cases
// ===========================================================

#[test]
fn fallocate_on_directory_is_rejected() {
    let root = ft_temp_root("falloc-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");

    let err = fs
        .fallocate_file("/docs", 0, 4096)
        .expect_err("fallocate on dir should error");
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "expected IsDirectory, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn zero_range_on_empty_file_is_noop() {
    let root = ft_temp_root("zero-empty");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/empty.bin", 0o644)
        .expect("create empty file");

    let record = fs
        .zero_range("/empty.bin", 0, 4096)
        .expect("zero_range on empty file");
    assert_eq!(record.size, 0, "size remains zero");

    let read = fs.read_file("/empty.bin").expect("read empty file");
    assert!(read.is_empty(), "empty file reads empty");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn fallocate_zero_length_is_noop() {
    let root = ft_temp_root("falloc-zero-len");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"zero-length fallocate test";
    fs.write_file("/file.bin", 0, bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let record = fs
        .fallocate_file("/file.bin", 0, 0)
        .expect("zero-length fallocate");
    assert_eq!(record.size, original_size, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn punch_hole_on_nonexistent_file_returns_not_found() {
    let root = ft_temp_root("punch-noent");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");

    let err = fs
        .punch_hole("/nonexistent.bin", 0, 4096)
        .expect_err("punch on nonexistent file should error");
    assert!(
        matches!(err, FileSystemError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn zero_range_on_nonexistent_file_returns_not_found() {
    let root = ft_temp_root("zero-noent");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");

    let err = fs
        .zero_range("/nonexistent.bin", 0, 4096)
        .expect_err("zero_range on nonexistent file should error");
    assert!(
        matches!(err, FileSystemError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn fallocate_file_on_nonexistent_path_returns_not_found() {
    let root = ft_temp_root("falloc-noent");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");

    let err = fs
        .fallocate_file("/nonexistent.bin", 0, 4096)
        .expect_err("fallocate on nonexistent file should error");
    assert!(
        matches!(err, FileSystemError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn write_after_punch_hole_preserves_new_data() {
    let root = ft_temp_root("write-after-punch");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let bytes: Vec<u8> = (0..chunk * 3).map(|i| (i % 233) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    fs.punch_hole("/file.bin", chunk as u64, chunk as u64)
        .expect("punch hole");

    let new_data: Vec<u8> = (0..chunk).map(|i| (i % 127) as u8).collect();
    fs.write_file("/file.bin", chunk as u64, &new_data)
        .expect("write into hole");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read[..chunk], &bytes[..chunk], "head preserved");
    assert_eq!(&read[chunk..chunk * 2], &new_data, "new data intact");
    assert_eq!(&read[chunk * 2..], &bytes[chunk * 2..], "tail preserved");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn persistence_zero_range_survives_reopen() {
    let root = ft_temp_root("zero-persist");
    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 239) as u8).collect();

    {
        let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
        fs.create_file("/file.bin", 0o644).expect("create file");
        fs.write_file("/file.bin", 0, &bytes).expect("write data");

        fs.zero_range("/file.bin", chunk as u64, chunk as u64)
            .expect("zero range");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(read.len(), total);
    assert_eq!(&read[..chunk], &bytes[..chunk]);
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "zeros survive reopen"
    );
    assert_eq!(&read[chunk * 2..], &bytes[chunk * 2..]);

    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn persistence_fallocate_survives_reopen() {
    let root = ft_temp_root("falloc-persist");
    let alloc_len = (content_chunk_size() * 2) as u64;

    {
        let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
        fs.create_file("/file.bin", 0o644).expect("create file");
        fs.fallocate_file("/file.bin", 0, alloc_len)
            .expect("fallocate");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(read.len(), alloc_len as usize);
    assert!(read.iter().all(|&b| b == 0), "zeros survive reopen");

    drop(fs);
    ft_cleanup(&root);
}

// ===========================================================
// Group 8: Collapse range
// ===========================================================

#[test]
fn collapse_range_middle_shifts_data_left_and_shrinks_file() {
    let root = ft_temp_root("collapse-middle");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 211) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let collapse_offset = chunk as u64;
    let collapse_length = chunk as u64;
    let record = fs
        .collapse_range("/file.bin", collapse_offset, collapse_length)
        .expect("collapse middle chunk");
    assert_eq!(
        record.size,
        total as u64 - collapse_length,
        "file size shrinks by collapse length"
    );

    let read = fs.read_file("/file.bin").expect("read after collapse");
    assert_eq!(read.len(), (total - chunk) as usize);
    // Prefix preserved
    assert_eq!(&read[..chunk], &bytes[..chunk], "prefix preserved");
    // Tail shifted left: bytes[chunk*2..chunk*3] moved to [chunk..chunk*2]
    assert_eq!(
        &read[chunk..],
        &bytes[chunk * 2..],
        "tail shifted left by collapse length"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn collapse_range_zero_length_is_noop() {
    let root = ft_temp_root("collapse-zero");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"collapse zero length test";
    fs.write_file("/file.bin", 0, bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let record = fs
        .collapse_range("/file.bin", 5, 0)
        .expect("zero-length collapse");
    assert_eq!(record.size, original_size, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn collapse_range_past_eof_is_noop() {
    let root = ft_temp_root("collapse-past-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello collapse past eof";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let record = fs
        .collapse_range("/file.bin", bytes.len() as u64 + 100, 4096)
        .expect("collapse past EOF returns Ok");
    assert_eq!(record.size, bytes.len() as u64, "size unchanged");

    let read = fs
        .read_file("/file.bin")
        .expect("read after no-op collapse");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn collapse_range_entire_file_results_in_empty_file() {
    let root = ft_temp_root("collapse-entire");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    let total = bytes.len() as u64;
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let record = fs
        .collapse_range("/file.bin", 0, total)
        .expect("collapse entire file");
    assert_eq!(record.size, 0, "file is empty");

    let read = fs.read_file("/file.bin").expect("read empty file");
    assert!(read.is_empty(), "content is empty");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn collapse_range_on_directory_is_rejected() {
    let root = ft_temp_root("collapse-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");

    let err = fs
        .collapse_range("/docs", 0, 4096)
        .expect_err("collapse on dir should error");
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "expected IsDirectory, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn collapse_range_on_nonexistent_file_returns_not_found() {
    let root = ft_temp_root("collapse-noent");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");

    let err = fs
        .collapse_range("/nonexistent.bin", 0, 4096)
        .expect_err("collapse on nonexistent file should error");
    assert!(
        matches!(err, FileSystemError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );

    ft_cleanup(&root);
}

// ===========================================================
// Group 9: Insert range
// ===========================================================

#[test]
fn insert_range_middle_shifts_data_right_and_grows_file() {
    let root = ft_temp_root("insert-middle");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 191) as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let insert_offset = chunk as u64;
    let insert_length = chunk as u64;
    let record = fs
        .insert_range("/file.bin", insert_offset, insert_length)
        .expect("insert middle");
    assert_eq!(
        record.size,
        total as u64 + insert_length,
        "file size grows by insert length"
    );

    let read = fs.read_file("/file.bin").expect("read after insert");
    assert_eq!(read.len(), total + chunk);
    // Prefix preserved
    assert_eq!(&read[..chunk], &bytes[..chunk], "prefix preserved");
    // Inserted region is zeros
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "inserted region is zeros"
    );
    // Tail shifted right
    assert_eq!(
        &read[chunk * 2..],
        &bytes[chunk..],
        "tail shifted right by insert length"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn insert_range_zero_length_is_noop() {
    let root = ft_temp_root("insert-zero");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"insert zero length test";
    fs.write_file("/file.bin", 0, bytes).expect("write data");
    let original_size = fs.stat("/file.bin").expect("stat").size;

    let record = fs
        .insert_range("/file.bin", 5, 0)
        .expect("zero-length insert");
    assert_eq!(record.size, original_size, "size unchanged");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(&read, bytes, "content unchanged");

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn insert_range_beyond_eof_extends_with_zeros() {
    let root = ft_temp_root("insert-past-eof");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes = b"hello insert past eof";
    fs.write_file("/file.bin", 0, bytes).expect("write data");

    let insert_offset = bytes.len() as u64 + 50;
    let insert_length = 64;
    let record = fs
        .insert_range("/file.bin", insert_offset, insert_length)
        .expect("insert beyond EOF");
    let expected_size = insert_offset + insert_length;
    assert_eq!(record.size, expected_size, "size extends past insert");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), expected_size as usize);
    assert_eq!(&read[..bytes.len()], bytes, "original data preserved");
    // Gap between end of data and insert offset is zeros
    let gap_end = insert_offset as usize;
    if gap_end > bytes.len() {
        assert!(
            read[bytes.len()..gap_end].iter().all(|&b| b == 0),
            "gap before inserted range is zeros"
        );
    }
    // Inserted region is zeros
    assert!(
        read[insert_offset as usize..][..insert_length as usize]
            .iter()
            .all(|&b| b == 0),
        "inserted region is zeros"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn insert_range_at_start_shifts_all_data_right() {
    let root = ft_temp_root("insert-start");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..128).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    let insert_length = 64usize;
    let record = fs
        .insert_range("/file.bin", 0, insert_length as u64)
        .expect("insert at start");
    assert_eq!(
        record.size,
        (bytes.len() + insert_length) as u64,
        "size grows"
    );

    let read = fs.read_file("/file.bin").expect("read");
    assert!(
        read[..insert_length].iter().all(|&b| b == 0),
        "inserted region at start is zeros"
    );
    assert_eq!(
        &read[insert_length..],
        &bytes,
        "original data shifted right"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn insert_range_on_directory_is_rejected() {
    let root = ft_temp_root("insert-dir");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_dir("/docs", 0o755).expect("create docs");

    let err = fs
        .insert_range("/docs", 0, 4096)
        .expect_err("insert on dir should error");
    assert!(
        matches!(err, FileSystemError::IsDirectory { .. }),
        "expected IsDirectory, got {err:?}"
    );

    ft_cleanup(&root);
}

#[test]
fn insert_range_on_nonexistent_file_returns_not_found() {
    let root = ft_temp_root("insert-noent");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");

    let err = fs
        .insert_range("/nonexistent.bin", 0, 4096)
        .expect_err("insert on nonexistent file should error");
    assert!(
        matches!(err, FileSystemError::NotFound { .. }),
        "expected NotFound, got {err:?}"
    );

    ft_cleanup(&root);
}

// ===========================================================
// Group 10: Combined operations + persistence
// ===========================================================

#[test]
fn collapse_then_insert_restores_original_size() {
    let root = ft_temp_root("collapse-insert");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..256).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    // Collapse a range, then insert zeros in the same place
    let collapse_len = 64usize;
    fs.collapse_range("/file.bin", 100, collapse_len as u64)
        .expect("collapse");
    fs.insert_range("/file.bin", 100, collapse_len as u64)
        .expect("insert zeros");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), bytes.len(), "size restored to original");
    // Prefix and tail preserved; middle is zeros from insert
    assert_eq!(&read[..100], &bytes[..100], "prefix preserved");
    assert!(
        read[100..100 + collapse_len].iter().all(|&b| b == 0),
        "inserted region is zeros"
    );
    assert_eq!(
        &read[100 + collapse_len..],
        &bytes[100 + collapse_len..],
        "tail preserved"
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn persistence_collapse_range_survives_reopen() {
    let root = ft_temp_root("collapse-persist");
    let chunk = content_chunk_size() as usize;
    let total = chunk * 3;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 199) as u8).collect();

    {
        let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
        fs.create_file("/file.bin", 0o644).expect("create file");
        fs.write_file("/file.bin", 0, &bytes).expect("write data");

        fs.collapse_range("/file.bin", chunk as u64, chunk as u64)
            .expect("collapse middle");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(read.len(), total - chunk, "size survives reopen");
    assert_eq!(&read[..chunk], &bytes[..chunk], "prefix survives reopen");
    assert_eq!(
        &read[chunk..],
        &bytes[chunk * 2..],
        "tail shifted survives reopen"
    );

    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn persistence_insert_range_survives_reopen() {
    let root = ft_temp_root("insert-persist");
    let chunk = content_chunk_size() as usize;
    let total = chunk * 2;
    let bytes: Vec<u8> = (0..total).map(|i| (i % 223) as u8).collect();

    {
        let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
        fs.create_file("/file.bin", 0o644).expect("create file");
        fs.write_file("/file.bin", 0, &bytes).expect("write data");

        fs.insert_range("/file.bin", chunk as u64, chunk as u64)
            .expect("insert middle");
        fs.sync_all().expect("sync");
    }

    let fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("reopen fs");
    let read = fs.read_file("/file.bin").expect("read after reopen");
    assert_eq!(read.len(), total + chunk, "size survives reopen");
    assert_eq!(&read[..chunk], &bytes[..chunk], "prefix survives reopen");
    assert!(
        read[chunk..chunk * 2].iter().all(|&b| b == 0),
        "zeros survive reopen"
    );
    assert_eq!(
        &read[chunk * 2..],
        &bytes[chunk..],
        "tail shifted survives reopen"
    );

    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn collapse_range_partial_chunk_shifts_correctly() {
    let root = ft_temp_root("collapse-partial");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..500).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    // Collapse a small range in the middle (not chunk-aligned)
    let offset = 73u64;
    let length = 29u64;
    fs.collapse_range("/file.bin", offset, length)
        .expect("collapse small range");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), bytes.len() - length as usize);
    assert_eq!(&read[..offset as usize], &bytes[..offset as usize]);
    assert_eq!(
        &read[offset as usize..],
        &bytes[offset as usize + length as usize..]
    );

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}

#[test]
fn insert_range_partial_chunk_shifts_correctly() {
    let root = ft_temp_root("insert-partial");
    let mut fs = LocalFileSystem::open_with_options(&root, ft_options()).expect("open fs");
    fs.create_file("/file.bin", 0o644).expect("create file");

    let bytes: Vec<u8> = (0..400).map(|i| i as u8).collect();
    fs.write_file("/file.bin", 0, &bytes).expect("write data");

    // Insert a small range at an unaligned offset
    let offset = 57u64;
    let length = 41u64;
    fs.insert_range("/file.bin", offset, length)
        .expect("insert small range");

    let read = fs.read_file("/file.bin").expect("read");
    assert_eq!(read.len(), bytes.len() + length as usize);
    assert_eq!(&read[..offset as usize], &bytes[..offset as usize]);
    let ins_end = offset as usize + length as usize;
    assert!(read[offset as usize..ins_end].iter().all(|&b| b == 0));
    assert_eq!(&read[ins_end..], &bytes[offset as usize..]);

    fs.sync_all().expect("sync");
    drop(fs);
    ft_cleanup(&root);
}
