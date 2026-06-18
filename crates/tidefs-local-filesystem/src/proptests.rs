// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#[cfg(test)]
use super::*;
use proptest::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn prop_temp_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "tidefs-proptest-{name}-{}-{nanos}",
        std::process::id()
    ))
}

fn prop_options() -> StoreOptions {
    StoreOptions {
        max_segment_bytes: 64 * 1024,
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

fn prop_cleanup(root: &std::path::Path) {
    let _ = fs::remove_dir_all(root);
}

/// Strategy: generate arbitrary byte vectors of various sizes.
fn arb_bytes() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..(FILESYSTEM_CONTENT_CHUNK_SIZE * 4 + 7))
}

/// Strategy: generate an offset + patch bytes for random writes.
fn arb_patch() -> impl Strategy<Value = (u64, Vec<u8>)> {
    (
        0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 3),
        prop::collection::vec(any::<u8>(), 1..512),
    )
}

// ── Roundtrip tests ──────────────────────────────────────────

proptest! {
    /// Write arbitrary content, read it back, verify byte-for-byte identity.
    #[test]
    fn proptest_write_read_roundtrip(bytes in arb_bytes()) {
        let root = prop_temp_root("write-read-roundtrip");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &bytes).expect("write file");

        let read_back = fs.read_file("/data.bin").expect("read file");
        prop_assert_eq!(read_back, bytes);

        prop_cleanup(&root);
    }

    /// Write content, random-write a patch, verify correct final bytes.
    #[test]
    fn proptest_write_patch_read_roundtrip(
        initial in arb_bytes(),
        (patch_offset, patch_bytes) in arb_patch(),
    ) {
        let root = prop_temp_root("write-patch-roundtrip");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &initial).expect("write initial");

        // Apply patch at a chunk-aligned offset.
        let chunk_sz = FILESYSTEM_CONTENT_CHUNK_SIZE as u64;
        let patch_offset = patch_offset.saturating_sub(patch_offset % chunk_sz);
        fs.write_file("/data.bin", patch_offset, &patch_bytes).expect("write patch");

        let read_back = fs.read_file("/data.bin").expect("read file");
        let mut expected = initial.clone();
        let po = patch_offset as usize;
        if po < expected.len() {
            let pb = patch_bytes.len().min(expected.len() - po);
            expected[po..po + pb].copy_from_slice(&patch_bytes[..pb]);
        } else if po > expected.len() {
            expected.resize(po, 0);
            expected.extend_from_slice(&patch_bytes);
        }
        prop_assert_eq!(read_back, expected);

        prop_cleanup(&root);
    }

    /// Truncate to a new size, verify bytes up to that size are preserved.
    #[test]
    fn proptest_truncate_roundtrip(
        initial in arb_bytes(),
        trunc_len in (0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 4)),
    ) {
        let root = prop_temp_root("truncate-roundtrip");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &initial).expect("write initial");

        fs.truncate_file("/data.bin", trunc_len).expect("truncate file");

        let read_back = fs.read_file("/data.bin").expect("read file");
        let expected: Vec<u8> = initial.iter().take(trunc_len as usize).copied().collect();
        prop_assert_eq!(read_back, expected);

        prop_cleanup(&root);
    }

    /// Persistence roundtrip: write, sync, drop, reopen, verify.
    #[test]
    fn proptest_persist_roundtrip(bytes in arb_bytes()) {
        let root = prop_temp_root("persist-roundtrip");
        {
            let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
            fs.create_file("/data.bin", 0o644).expect("create file");
            fs.write_file("/data.bin", 0, &bytes).expect("write file");
            fs.sync_all().expect("sync");
        }
        {
            let fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("reopen fs");
            let read_back = fs.read_file("/data.bin").expect("read file");
            prop_assert_eq!(read_back, bytes);
        }
        prop_cleanup(&root);
    }

    /// Multi-file write + read roundtrip.
    #[test]
    fn proptest_multi_file_roundtrip(
        files in prop::collection::vec(arb_bytes(), 1..8),
    ) {
        let root = prop_temp_root("multi-file-roundtrip");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        for (i, data) in files.iter().enumerate() {
            let path = format!("/file_{i}.bin");
            fs.create_file(&path, 0o644).expect("create file");
            fs.write_file(&path, 0, data).expect("write file");
        }
        for (i, data) in files.iter().enumerate() {
            let path = format!("/file_{i}.bin");
            let read_back = fs.read_file(&path).expect("read file");
            prop_assert_eq!(&read_back, data);
        }
        prop_cleanup(&root);
    }

    /// Chunked content preserves unchanged chunks after random writes.
    #[test]
    fn proptest_random_write_preserves_unchanged_chunks(
        initial in arb_bytes(),
        (patch_offset, patch_bytes) in arb_patch(),
    ) {
        let root = prop_temp_root("preserve-chunks");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &initial).expect("write initial");

        let record_before = fs.stat("/data.bin").expect("stat before patch");
        let content_key_before = content_object_key_for_version(record_before.inode_id, record_before.data_version);
        let bytes_before = fs.store.primary_store().get(content_key_before)
            .expect("read content obj")
            .expect("content obj exists before");
        let manifest_before = decode_content_manifest(&bytes_before).expect("decode manifest before");

        let chunk_sz = FILESYSTEM_CONTENT_CHUNK_SIZE as u64;
        let patch_offset = patch_offset.min(initial.len() as u64);
        fs.write_file("/data.bin", patch_offset, &patch_bytes).expect("write patch");

        let record_after = fs.stat("/data.bin").expect("stat after patch");
        let content_key_after = content_object_key_for_version(record_after.inode_id, record_after.data_version);
        let bytes_after = fs.store.primary_store().get(content_key_after)
            .expect("read content obj after")
            .expect("content obj exists after");
        let manifest_after = decode_content_manifest(&bytes_after).expect("decode manifest after");

        let patch_start_chunk = patch_offset / chunk_sz;
        let patch_end = patch_offset + patch_bytes.len() as u64;
        let patch_end_chunk = if patch_end == 0 { 0 } else { (patch_end - 1) / chunk_sz };

        for (i, before_chunk) in manifest_before.chunks.iter().enumerate() {
            let ci = i as u64;
            if ci < patch_start_chunk || ci > patch_end_chunk {
                if let Some(after_chunk) = manifest_after.chunks.get(i) {
                    if !before_chunk.is_hole() && !after_chunk.is_hole() {
                        // Use assert! instead of prop_assert_eq! to avoid format_args! closure capture
                        assert!(
                            before_chunk.data_version == after_chunk.data_version,
                            "chunk index {ci}: data_version changed from {} to {} but should be preserved",
                            before_chunk.data_version,
                            after_chunk.data_version,
                        );
                    }
                }
            }
        }

        prop_cleanup(&root);
    }
}

#[test]
fn proptest_regression_empty_file_roundtrip() {
    // Regression: zero-length files should roundtrip correctly.
    let root = prop_temp_root("empty-roundtrip");
    let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
    fs.create_file("/empty.bin", 0o644).expect("create file");
    let read_back = fs.read_file("/empty.bin").expect("read empty");
    assert!(read_back.is_empty());
    fs.sync_all().expect("sync");
    drop(fs);

    let fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("reopen fs");
    let read_back = fs.read_file("/empty.bin").expect("read empty after reopen");
    assert!(read_back.is_empty());
    prop_cleanup(&root);
}

// ── Chunked-file-layout roundtrip tests ──────────────────────

proptest! {
    /// Manifest encode → decode roundtrip: create an arbitrary manifest (with holes),
    /// encode it, decode it, and verify byte-for-byte identity.
    #[test]
    fn proptest_manifest_encode_decode_roundtrip(
        inode_id in (1u64..100_000),
        data_version in (1u64..1_000_000),
        file_size in (0u64..(FILESYSTEM_CONTENT_CHUNK_SIZE as u64 * 8 + 1)),
        chunk_refs in arb_chunk_refs(),
    ) {
        let manifest = ContentManifestObject {
            inode_id: InodeId::new(inode_id),
            data_version,
            file_size,
            chunk_size: content_chunk_size(),
            chunks: chunk_refs,
        };

        let encoded = encode_content_manifest(&manifest);
        let decoded = decode_content_manifest(&encoded)
            .expect("decode content manifest roundtrip");

        prop_assert_eq!(manifest.clone(), decoded.clone());

        // Also verify sparse encoding roundtrips.
        let sparse_encoded = encode_content_manifest_sparse(&decoded);
        let sparse_decoded = decode_content_manifest(&sparse_encoded)
            .expect("decode sparse content manifest roundtrip");
        prop_assert_eq!(decoded, sparse_decoded);
    }

    /// Content chunk encode → decode roundtrip.
    #[test]
    fn proptest_content_chunk_encode_decode_roundtrip(
        inode_id in (1u64..100_000),
        data_version in (1u64..1_000_000),
        chunk_index in (0u64..1000),
        payload in prop::collection::vec(any::<u8>(), 0..(FILESYSTEM_CONTENT_CHUNK_SIZE)),
    ) {
        let record = InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(inode_id),
            generation: Generation::new(data_version),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: payload.len() as u64,
            data_version,
            metadata_version: data_version,
            posix_time: crate::types::PosixTimeRecord::synthetic(1_i64),
            xattrs: Default::default(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
        };
        let encoded = encode_content_chunk(&record, chunk_index, &payload, &ContentCompressionPolicy::zstd_default());
        let decoded = decode_content_chunk(&encoded)
            .expect("decode content chunk roundtrip");

        prop_assert_eq!(decoded.inode_id, record.inode_id);
        prop_assert_eq!(decoded.data_version, record.data_version);
        prop_assert_eq!(decoded.chunk_index, chunk_index);
        prop_assert_eq!(decoded.bytes, payload);
    }

    /// Write content, then verify the content manifest structure matches the written bytes.
    #[test]
    fn proptest_manifest_structure_consistent_with_content(
        bytes in arb_bytes(),
    ) {
        let root = prop_temp_root("manifest-content-consistency");
        let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
        fs.create_file("/data.bin", 0o644).expect("create file");
        fs.write_file("/data.bin", 0, &bytes).expect("write file");

        let record = fs.stat("/data.bin").expect("stat file");
        let content_key = content_object_key_for_version(record.inode_id, record.data_version);
        let manifest_bytes = fs.store.primary_store().get(content_key)
            .expect("read content obj")
            .expect("content obj exists");
        let manifest = decode_content_manifest(&manifest_bytes).expect("decode manifest");

        // Manifest metadata matches the inode.
        prop_assert_eq!(manifest.inode_id, record.inode_id);
        prop_assert_eq!(manifest.data_version, record.data_version);
        prop_assert_eq!(manifest.file_size, record.size);
        prop_assert_eq!(manifest.chunk_size, content_chunk_size());

        // If file is non-empty, chunk count must be non-zero and cover the file.
        if bytes.is_empty() {
            prop_assert!(manifest.chunks.is_empty(),
                "zero-length file must have no chunks, got {}", manifest.chunks.len());
        } else {
            let expected_chunk_count = content_chunk_count(record.size)
                .expect("chunk count for valid size") as usize;
            prop_assert_eq!(manifest.chunks.len(), expected_chunk_count,
                "chunk count mismatch for size {}", record.size);

            // Each chunk covers the right byte range & has the right data version.
            let chunk_sz = content_chunk_size() as u64;
            let mut offset: u64 = 0;
            for (i, chunk) in manifest.chunks.iter().enumerate() {
                prop_assert_eq!(chunk.chunk_index, i as u64);
                prop_assert_eq!(chunk.data_version, record.data_version);
                let expected_len = ((record.size - offset).min(chunk_sz)) as u32;
                prop_assert_eq!(chunk.len, expected_len,
                    "chunk {}: expected len {}, got {}", i, expected_len, chunk.len);
                offset += chunk_sz;
            }
        }

        // Read the full content back and verify.
        let read_back = fs.read_file("/data.bin").expect("read file");
        prop_assert_eq!(read_back, bytes);

        prop_cleanup(&root);
    }

    /// Chunked-layout reopen roundtrip: write, sync, reopen, verify manifest + content.
    #[test]
    fn proptest_chunked_layout_reopen_roundtrip(
        bytes in arb_bytes(),
    ) {
        let root = prop_temp_root("chunked-reopen");
        let manifest_before: ContentManifestObject;
        {
            let mut fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("open fs");
            fs.create_file("/data.bin", 0o644).expect("create file");
            fs.write_file("/data.bin", 0, &bytes).expect("write file");

            let record = fs.stat("/data.bin").expect("stat");
            let content_key = content_object_key_for_version(record.inode_id, record.data_version);
            let raw = fs.store.primary_store().get(content_key)
                .expect("read")
                .expect("exists");
            manifest_before = decode_content_manifest(&raw).expect("decode before");

            fs.sync_all().expect("sync");
        }
        {
            let fs = LocalFileSystem::open_with_options(&root, prop_options()).expect("reopen fs");
            let record = fs.stat("/data.bin").expect("stat after reopen");
            let content_key = content_object_key_for_version(record.inode_id, record.data_version);
            let raw = fs.store.primary_store().get(content_key)
                .expect("read after reopen")
                .expect("exists after reopen");
            let manifest_after = decode_content_manifest(&raw).expect("decode after reopen");

            prop_assert_eq!(manifest_before, manifest_after,
                "manifest must be byte-identical after reopen");

            let read_back = fs.read_file("/data.bin").expect("read after reopen");
            prop_assert_eq!(read_back, bytes);
        }
        prop_cleanup(&root);
    }
}

// ── Arbitrary strategies for chunked-layout tests ────────────

/// Generate an arbitrary vector of ContentChunkRef with optional holes.
fn arb_chunk_refs() -> impl Strategy<Value = Vec<ContentChunkRef>> {
    prop::collection::vec(arb_chunk_ref(), 0..17)
}

/// Generate a single arbitrary ContentChunkRef.
fn arb_chunk_ref() -> impl Strategy<Value = ContentChunkRef> {
    (
        0u64..1000,                                   // chunk_index
        1u64..1_000_000,                              // data_version
        0u32..(FILESYSTEM_CONTENT_CHUNK_SIZE as u32), // len
    )
        .prop_map(|(chunk_index, data_version, len)| ContentChunkRef {
            chunk_index,
            data_version,
            len,
            checksum: IntegrityDigest64(1),
            placement_receipt_generation: 0,
        })
}

#[test]
fn proptest_regression_empty_manifest_roundtrip() {
    let manifest = ContentManifestObject {
        inode_id: InodeId::new(42),
        data_version: 1,
        file_size: 0,
        chunk_size: content_chunk_size(),
        chunks: Vec::new(),
    };
    let encoded = encode_content_manifest(&manifest);
    let decoded = decode_content_manifest(&encoded).expect("decode empty manifest");
    assert_eq!(manifest, decoded);
}
