// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration test: defrag a file then verify reads return correct data.
//!
//! Exercises the TIDEFS_IOC_DEFRAG dispatch path through the adapter's
//! public API, then validates that subsequent reads produce the data
//! that was written before defrag. This confirms that defrag does not
//! corrupt the extent map or lose logical-to-physical mappings.
//!
//! Uses the adapter's dispatch API directly (bypassing FUSE mount) so
//! the test runs without /dev/fuse or kernel FUSE support.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_local_filesystem::{
    human::local_filesystem::StoreOptions, vfs_engine_impl::VfsLocalFileSystem, LocalFileSystem,
    RootAuthenticationKey,
};
use tidefs_posix_filesystem_adapter_daemon::fuse_vfs_adapter::FuseVfsAdapter;
use tidefs_posix_filesystem_adapter_daemon::fusewire::DefragIoctlInput;
use tidefs_types_vfs_core::RequestCtx;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Harness {
    adapter: FuseVfsAdapter,
    store_dir: PathBuf,
}

impl Harness {
    fn new() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let store_dir =
            std::env::temp_dir().join(format!("tidefs-defrag-read-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&store_dir).expect("create store dir");

        let filesystem = LocalFileSystem::open_with_root_authentication_key(
            &store_dir,
            StoreOptions::default(),
            RootAuthenticationKey::demo_key(),
        )
        .expect("open local filesystem");
        let engine = VfsLocalFileSystem::new(filesystem);
        let adapter = FuseVfsAdapter::new(Box::new(engine)).expect("create adapter");
        Self { adapter, store_dir }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.store_dir);
    }
}

fn request_ctx() -> RequestCtx {
    RequestCtx {
        uid: 0,
        gid: 0,
        pid: 1,
        umask: 0o022,
        groups: vec![0],
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Write a file, defrag it, then read and verify data correctness.
#[test]
fn defrag_preserves_file_data() {
    let harness = Harness::new();
    let ctx = request_ctx();

    // Create a file and write 12 KiB in three blocks (potentially
    // creating 3 separate extents through the allocator).
    let create_dispatch = harness
        .adapter
        .dispatch_create(&ctx, 1, b"defrag_test_file", 0o644, libc::O_RDWR as u32)
        .expect("create file");
    let ino = create_dispatch.inode();
    let fh = create_dispatch.file_handle();

    let data: Vec<u8> = (0..(3 * 4096u64)).map(|i| (i % 251) as u8).collect();

    let written = harness
        .adapter
        .dispatch_write(&ctx, ino, fh, 0, &data, 0)
        .expect("write data");
    assert_eq!(written, data.len() as u32);

    // Defrag the file via the ioctl dispatch path.
    let defrag_input = DefragIoctlInput { ino, flags: 0 };
    let _ = harness.adapter.dispatch_defrag(&ctx, defrag_input);

    // Read the entire file using the same handle and verify data integrity.
    let read_data = harness
        .adapter
        .dispatch_read(&ctx, ino, fh, 0, data.len() as u32, None)
        .expect("read file after defrag");

    assert_eq!(
        read_data.len(),
        data.len(),
        "read size mismatch after defrag"
    );
    assert_eq!(
        read_data, data,
        "data corruption after defrag: read data differs from written data"
    );
}

/// Write multiple files under a directory, recursively defrag the
/// directory, then read each file and verify data integrity.
#[test]
fn defrag_directory_preserves_file_data() {
    let harness = Harness::new();
    let ctx = request_ctx();

    // Create a subdirectory.
    let dir_attr = harness
        .adapter
        .dispatch_mkdir(&ctx, 1, b"defrag_integ_dir", 0o755)
        .expect("mkdir");

    // Create two files with data.
    let file_specs: Vec<(&[u8], Vec<u8>)> = vec![
        (b"file_a", (0..4096u64).map(|i| (i % 251) as u8).collect()),
        (
            b"file_b",
            (0..8192u64).map(|i| ((i + 128) % 251) as u8).collect(),
        ),
    ];

    let mut file_inos: Vec<u64> = Vec::new();
    let mut file_fhs: Vec<u64> = Vec::new();
    for (name, data) in &file_specs {
        let dispatch = harness
            .adapter
            .dispatch_create(
                &ctx,
                dir_attr.inode_id.get(),
                name,
                0o644,
                libc::O_RDWR as u32,
            )
            .expect("create file in dir");
        let ino = dispatch.inode();
        let fh = dispatch.file_handle();

        let written = harness
            .adapter
            .dispatch_write(&ctx, ino, fh, 0, data, 0)
            .expect("write file");
        assert_eq!(written, data.len() as u32);

        file_inos.push(ino);
        file_fhs.push(fh);
    }

    // Recursively defrag the directory.
    let defrag_input = DefragIoctlInput {
        ino: dir_attr.inode_id.get(),
        flags: 1, // recursive
    };
    let _ = harness.adapter.dispatch_defrag(&ctx, defrag_input);

    // Verify each file's data.
    for (i, (_, expected_data)) in file_specs.iter().enumerate() {
        let read_data = harness
            .adapter
            .dispatch_read(
                &ctx,
                file_inos[i],
                file_fhs[i],
                0,
                expected_data.len() as u32,
                None,
            )
            .expect("read file after defrag");

        assert_eq!(
            read_data, *expected_data,
            "data corruption for file {i} after directory defrag"
        );
    }
}
