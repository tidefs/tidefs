//! Large-file sequential and sparse read/write FUSE integration tests.
//!
//! Exercises multi-block I/O, sparse-file hole semantics, block-unaligned
//! access, append beyond EOF, mid-file overwrite, and concurrent read safety
//! through a real kernel FUSE mount.
//!
//! Run with:
//!   cargo test -p tidefs-posix-filesystem-adapter-daemon --test fuse_large_file_read_write

mod fuse_mount_harness;

use fuse_mount_harness::{
    create_read_write, open_read_only, patterned_bytes, read_all, MountedVfs,
};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Skip the current test when FUSE is unavailable.
macro_rules! require_fuse {
    () => {
        if !fuse_mount_harness::fuse_available() {
            eprintln!(
                "SKIP: /dev/fuse not available — integration test requires FUSE kernel module"
            );
            return;
        }
    };
}

/// Open an existing mounted file for writing without truncation or creation.
fn open_write_only(path: &Path) -> File {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open mounted file for writing")
}

/// Assert every byte in the slice is zero.
fn assert_all_zero(bytes: &[u8]) {
    assert!(
        bytes.iter().all(|b| *b == 0),
        "expected all-zero bytes, found non-zero values"
    );
}

/// Write a byte slice at a specific offset using lseek, without affecting the
/// file position for subsequent reads.
fn pwrite_all(file: &mut File, buf: &[u8], offset: u64) {
    file.seek(SeekFrom::Start(offset))
        .expect("seek to write offset");
    file.write_all(buf).expect("write at offset");
}

/// Read exactly `len` bytes starting at `offset` into a new Vec<u8>.
fn pread_exact(file: &mut File, offset: u64, len: usize) -> Vec<u8> {
    file.seek(SeekFrom::Start(offset))
        .expect("seek to read offset");
    let mut buf = vec![0u8; len];
    file.read_exact(&mut buf).expect("read at offset");
    buf
}

// ===========================================================================
// Test 1: sequential_write_256kb_read_back
// ===========================================================================

/// Write 256 KB of deterministic patterned bytes, read back in chunks,
/// and verify byte-for-byte equality.
#[test]
fn sequential_write_256kb_read_back() {
    require_fuse!();
    let mnt = MountedVfs::new("large-seq-rw", &["seq256.bin"], &[]);
    let path = mnt.path("/seq256.bin");
    let content = patterned_bytes(256 * 1024);

    // Write the full 256 KB
    {
        let mut file = create_read_write(&path);
        file.write_all(&content).expect("write 256 KB");
        file.flush().expect("flush 256 KB");
    }

    // Verify file size
    let meta = fs::metadata(&path).expect("stat after write");
    assert_eq!(meta.len(), 256 * 1024, "file size must be 256 KB");

    // Read back the entire file
    let readback = read_all(&path);
    assert_eq!(readback.len(), 256 * 1024);
    assert_eq!(readback, content, "byte-for-byte comparison must match");

    // Read back in 4 KB chunks to exercise block-boundary crossings
    let mut file = open_read_only(&path);
    for chunk_start in (0..256 * 1024).step_by(4096) {
        let chunk = pread_exact(&mut file, chunk_start as u64, 4096);
        assert_eq!(
            chunk,
            content[chunk_start..chunk_start + 4096],
            "chunk at offset {chunk_start} must match"
        );
    }
}

// ===========================================================================
// Test 2: sparse_file_hole_reads_as_zeroes
// ===========================================================================

/// Write data at offset 0 and offset 128 KB, creating a hole between them.
/// Verify the hole reads as zeroes and the non-hole data is intact.
#[test]
fn sparse_file_hole_reads_as_zeroes() {
    require_fuse!();
    let mnt = MountedVfs::new("sparse-hole", &["sparse.bin"], &[]);
    let path = mnt.path("/sparse.bin");

    let head = b"HEAD_DATA_AT_OFFSET_ZERO___"; // 28 bytes
    let tail = b"TAIL_DATA_AT_OFFSET_128KB___"; // 28 bytes
    let hole_start = head.len() as u64;
    let tail_offset = 128 * 1024u64;

    {
        let mut file = create_read_write(&path);

        // Write head at offset 0
        file.write_all(head).expect("write head");
        // Write tail at offset 128 KB (creates a hole from ~28 to 131072)
        file.seek(SeekFrom::Start(tail_offset))
            .expect("seek to 128 KB");
        file.write_all(tail).expect("write tail");
        file.flush().expect("flush sparse file");
    }

    // Verify file size
    let meta = fs::metadata(&path).expect("stat sparse file");
    let expected_size = tail_offset + tail.len() as u64;
    assert_eq!(
        meta.len(),
        expected_size,
        "file size must include the hole and tail"
    );

    // Read head region
    let mut file = open_read_only(&path);
    let head_read = pread_exact(&mut file, 0, head.len());
    assert_eq!(head_read, head, "head data must be intact");

    // Read hole region (offset head.len() to tail_offset)
    let hole_size = (tail_offset - hole_start) as usize;
    let hole_read = pread_exact(&mut file, hole_start, hole_size);
    assert_all_zero(&hole_read);

    // Read tail region
    let tail_read = pread_exact(&mut file, tail_offset, tail.len());
    assert_eq!(tail_read, tail, "tail data must be intact");

    // Read full file from start — head + zeroes + tail
    let full = read_all(&path);
    assert_eq!(full.len(), expected_size as usize);
    assert_eq!(&full[..head.len()], head);
    assert_all_zero(&full[head.len()..tail_offset as usize]);
    assert_eq!(&full[tail_offset as usize..], tail);
}

// ===========================================================================
// Test 3: block_unaligned_write_read
// ===========================================================================

/// Write data at an offset that crosses a 4 KB block boundary (offset 4090,
/// write 100 bytes) and verify both the partial-block prefix, the crossing
/// region, and the partial-block suffix read back correctly.
#[test]
fn block_unaligned_write_read() {
    require_fuse!();
    let mnt = MountedVfs::new("unaligned-rw", &["unalign.bin"], &[]);
    let path = mnt.path("/unalign.bin");

    // First, write a known background pattern that will be partially overwritten
    let bg = patterned_bytes(8192); // two full blocks
    {
        let mut file = create_read_write(&path);
        file.write_all(&bg).expect("write background");
        file.flush().expect("flush background");
    }

    // Overwrite at offset 4090, 100 bytes (spanning block boundary at 4096)
    let unaligned_data: Vec<u8> = (0..100)
        .map(|i: i32| (i.wrapping_mul(7) % 256) as u8)
        .collect();
    {
        let mut file = open_write_only(&path);
        pwrite_all(&mut file, &unaligned_data, 4090);
        file.flush().expect("flush unaligned overwrite");
    }

    // Read back: prefix (0..4090) from bg, overwrite region, suffix (4190..8192) from bg
    let full = read_all(&path);
    assert_eq!(full.len(), 8192);

    // Prefix: unmangled background bytes
    assert_eq!(&full[..4090], &bg[..4090]);

    // Overwritten region
    assert_eq!(&full[4090..4190], &unaligned_data[..]);

    // Suffix: unmangled background bytes
    assert_eq!(&full[4190..8192], &bg[4190..8192]);
}

// ===========================================================================
// Test 4: append_write_beyond_eof
// ===========================================================================

/// Create a small file, then lseek beyond EOF and write data. Verify the
/// resulting file size includes the gap (hole + written data) and that the
/// written data is at the expected offset.
#[test]
fn append_write_beyond_eof() {
    require_fuse!();
    let mnt = MountedVfs::new("append-beyond-eof", &["beyond.bin"], &[]);
    let path = mnt.path("/beyond.bin");

    let initial = b"small start";
    {
        let mut file = create_read_write(&path);
        file.write_all(initial).expect("write initial");
        file.flush().expect("flush initial");
    }

    // Seek to 200 KB and write 50 KB
    let beyond_offset = 200 * 1024u64;
    let append_data = patterned_bytes(50 * 1024);
    {
        let mut file = open_write_only(&path);
        file.seek(SeekFrom::Start(beyond_offset))
            .expect("seek to 200 KB");
        file.write_all(&append_data)
            .expect("write 50 KB at 200 KB offset");
        file.flush().expect("flush append beyond EOF");
    }

    // Verify size: 200 KB + 50 KB
    let meta = fs::metadata(&path).expect("stat after append beyond EOF");
    let expected_size = beyond_offset + append_data.len() as u64;
    assert_eq!(
        meta.len(),
        expected_size,
        "size must be 200 KB + 50 KB = 250 KB"
    );

    // Read initial region
    let full = read_all(&path);
    assert_eq!(full.len(), expected_size as usize);
    assert_eq!(&full[..initial.len()], initial);

    // Hole from initial.len() to beyond_offset must be zeroes
    let hole_start = initial.len();
    let hole_end = beyond_offset as usize;
    assert_all_zero(&full[hole_start..hole_end]);

    // Written data at beyond_offset
    assert_eq!(&full[hole_end..], append_data);
}

// ===========================================================================
// Test 5: overwrite_middle_preserves_ends
// ===========================================================================

/// Write a full patterned buffer, then overwrite a middle section. Verify
/// the prefix and suffix are unchanged while the overwritten section
/// contains the new data.
#[test]
fn overwrite_middle_preserves_ends() {
    require_fuse!();
    let mnt = MountedVfs::new("overwrite-mid", &["overmid.bin"], &[]);
    let path = mnt.path("/overmid.bin");

    let original = patterned_bytes(64 * 1024); // 64 KB
    {
        let mut file = create_read_write(&path);
        file.write_all(&original).expect("write 64 KB original");
        file.flush().expect("flush original");
    }

    // Overwrite bytes 20 KB .. 44 KB with fresh data
    let overwrite_start = 20 * 1024;
    let overwrite_len = 24 * 1024;
    let overwrite_data = patterned_bytes(overwrite_len)
        .iter()
        .map(|b| b.wrapping_add(1))
        .collect::<Vec<u8>>();

    {
        let mut file = open_write_only(&path);
        pwrite_all(&mut file, &overwrite_data, overwrite_start as u64);
        file.flush().expect("flush overwrite");
    }

    let readback = read_all(&path);
    assert_eq!(readback.len(), 64 * 1024, "file size must not change");

    // Prefix unchanged
    assert_eq!(
        &readback[..overwrite_start],
        &original[..overwrite_start],
        "prefix before overwrite must be unchanged"
    );

    // Overwritten region
    assert_eq!(
        &readback[overwrite_start..overwrite_start + overwrite_len],
        &overwrite_data,
        "overwritten region must contain new data"
    );

    // Suffix unchanged
    let suffix_start = overwrite_start + overwrite_len;
    assert_eq!(
        &readback[suffix_start..],
        &original[suffix_start..],
        "suffix after overwrite must be unchanged"
    );
}

// ===========================================================================
// Test 6: concurrent_reads_during_write
// ===========================================================================

/// Open two file descriptors for reading on the same file, issue a write
/// on a third FD, then verify that the existing read handles observe
/// consistent data (either the old or new state, not torn).
///
/// Note: POSIX does not guarantee atomicity for multi-byte reads during
/// concurrent writes beyond the read(2) syscall itself. This test verifies
/// that the FUSE dispatch does not crash or return garbage, and that a
/// read after the write completes sees the updated data.
#[test]
fn concurrent_reads_during_write() {
    require_fuse!();
    let mnt = MountedVfs::new("concurrent-rw", &["concurrent.bin"], &[]);
    let path = mnt.path("/concurrent.bin");

    // Seed with initial data
    let initial = patterned_bytes(8192);
    {
        let mut file = create_read_write(&path);
        file.write_all(&initial).expect("write initial data");
        file.flush().expect("flush initial data");
    }

    // Open two read handles before the write
    let mut reader1 = open_read_only(&path);
    let mut reader2 = open_read_only(&path);

    // Verify both readers see the initial data
    let mut buf1 = vec![0u8; 8192];
    reader1.read_exact(&mut buf1).expect("reader1 read initial");
    assert_eq!(buf1, initial);

    let mut buf2 = vec![0u8; 8192];
    reader2.read_exact(&mut buf2).expect("reader2 read initial");
    assert_eq!(buf2, initial);

    // Write new data
    let updated: Vec<u8> = initial.iter().map(|b| b.wrapping_add(1)).collect();
    {
        let mut writer = open_write_only(&path);
        writer.seek(SeekFrom::Start(0)).expect("seek to start");
        writer.write_all(&updated).expect("write updated data");
        writer.flush().expect("flush updated data");
    }

    // Re-seek readers and read again — they should see updated data
    reader1.seek(SeekFrom::Start(0)).expect("reader1 seek back");
    let mut buf1_after = vec![0u8; 8192];
    reader1
        .read_exact(&mut buf1_after)
        .expect("reader1 read after write");
    assert_eq!(
        buf1_after, updated,
        "reader1 must see updated data after write"
    );

    reader2.seek(SeekFrom::Start(0)).expect("reader2 seek back");
    let mut buf2_after = vec![0u8; 8192];
    reader2
        .read_exact(&mut buf2_after)
        .expect("reader2 read after write");
    assert_eq!(
        buf2_after, updated,
        "reader2 must see updated data after write"
    );

    // Open a fresh reader and verify data is correct
    let readback = read_all(&path);
    assert_eq!(readback, updated, "fresh read must see updated data");
}

// ===========================================================================
// Test 7: large_file_survives_remount
// ===========================================================================

/// Write 256 KB, unmount, remount, and verify data integrity survives.
#[test]
fn large_file_survives_remount() {
    require_fuse!();
    let mut mnt = MountedVfs::new("large-remount", &["persist256.bin"], &[]);
    let path = mnt.path("/persist256.bin");
    let content = patterned_bytes(256 * 1024);

    // Write and fsync
    {
        let mut file = create_read_write(&path);
        file.write_all(&content).expect("write 256 KB");
        file.flush().expect("flush 256 KB");
    }
    File::open(&path)
        .expect("reopen for fsync")
        .sync_all()
        .expect("fsync");

    mnt.remount();

    let remounted = mnt.path("/persist256.bin");
    let meta = fs::metadata(&remounted).expect("stat after remount");
    assert_eq!(meta.len(), 256 * 1024, "size must survive remount");

    let readback = read_all(&remounted);
    assert_eq!(readback, content, "256 KB data must survive remount");
}
