// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scrub pipeline for block-level integrity verification.
//!
//! The scrub module walks local filesystem content blocks and verifies
//! their checksums using the `BlockChecksum` trait from `checksum.rs`.
//! It is consumed by the online verifier and reports corruptions that
//! the resolver (#590 / PC-019B.3) can attempt to repair.
//!
//! This module implements PC-019B.2 (scrub pipeline) using the
//! `FastBlockChecksum` and `ProductionBlockChecksum` implementations
//! from PC-019B.1 (#588).

use std::collections::BTreeMap;

use tidefs_local_object_store::{checksum64, IntegrityDigest64, LocalObjectStore};
use tidefs_types_vfs_core::InodeId;

use crate::checksum::{BlockChecksum, FastBlockChecksum};
use crate::content::read_content_layout_from_store;
use crate::encoding::decode_content;
use crate::encoding::split_inline_checksum;
use crate::object_keys::{content_chunk_object_key_for_version, content_object_key_for_version};
use crate::records::ContentChunkRef;
use crate::types::InodeRecord;
use crate::ContentLayout;
use crate::Result;
pub(crate) use crate::types::{ScrubBlockId, ScrubBlockKind};

// ── Scrub data types ──────────────────────────────────────────────────

/// Outcome of verifying a single content block.
#[derive(Clone, Debug)]
pub(crate) enum ScrubBlockOutcome {
    /// Block checksum verified successfully.
    Clean,
    /// Checksum mismatch detected.
    Corrupt {
        #[allow(dead_code)]
        // INTENT: scrub types for planned checksum verification and repair pipeline
        expected: IntegrityDigest64,
        #[allow(dead_code)]
        // INTENT: scrub types for planned checksum verification and repair pipeline
        actual: IntegrityDigest64,
    },
    #[allow(dead_code)] // INTENT: scrub types for planned checksum verification and repair pipeline
    /// Block could not be read from the store.
    Unreadable(String),
    #[allow(dead_code)] // INTENT: scrub types for planned checksum verification and repair pipeline
    /// Block has no applicable checksum (prior-generation format or metadata gap).
    NoChecksum,
}

/// Record of a single corrupt or unreadable block.
#[derive(Clone, Debug)]
pub(crate) struct ScrubViolation {
    pub block_id: ScrubBlockId,
    pub key_hex: String,
    pub outcome: ScrubBlockOutcome,
}

/// Full scrub report.
#[derive(Clone, Debug)]
pub(crate) struct ScrubReport {
    pub blocks_scanned: u64,
    pub blocks_clean: u64,
    pub blocks_corrupt: u64,
    pub blocks_unreadable: u64,
    pub blocks_no_checksum: u64,
    pub violations: Vec<ScrubViolation>,
}

impl ScrubReport {
    pub(crate) fn empty() -> Self {
        Self {
            blocks_scanned: 0,
            blocks_clean: 0,
            blocks_corrupt: 0,
            blocks_unreadable: 0,
            blocks_no_checksum: 0,
            violations: Vec::new(),
        }
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

// ── Scrub implementation ──────────────────────────────────────────────

/// Scrub a single content block using the fast checksum verifier.
///
/// Reads `bytes` from the store, computes the fast checksum, and compares
/// against the stored digest in `chunk_ref`.
pub(crate) fn scrub_content_chunk(
    store: &LocalObjectStore,
    inode_id: InodeId,
    chunk_ref: &ContentChunkRef,
) -> ScrubBlockOutcome {
    // Hole (sparse) chunks have no backing object-store data.
    if chunk_ref.is_hole() {
        return ScrubBlockOutcome::Clean;
    }
    let key = content_chunk_object_key_for_version(
        inode_id,
        chunk_ref.data_version,
        chunk_ref.chunk_index,
    );
    let bytes = match store.get(key) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return ScrubBlockOutcome::Unreadable(format!(
                "content chunk {}.{}.{} not found",
                inode_id.get(),
                chunk_ref.data_version,
                chunk_ref.chunk_index
            ));
        }
        Err(err) => {
            return ScrubBlockOutcome::Unreadable(err.to_string());
        }
    };

    let actual = FastBlockChecksum::compute(&bytes);
    if actual != chunk_ref.checksum {
        return ScrubBlockOutcome::Corrupt {
            expected: chunk_ref.checksum,
            actual,
        };
    }

    ScrubBlockOutcome::Clean
}

/// Scrub inline content, verifying the checksum suffix added by #588.
pub(crate) fn scrub_inline_content(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
) -> ScrubBlockOutcome {
    let key = content_object_key_for_version(inode_id, record.data_version);
    let bytes = match store.get(key) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            return ScrubBlockOutcome::Unreadable(format!(
                "inline content {}.{} not found",
                inode_id.get(),
                record.data_version
            ));
        }
        Err(err) => {
            return ScrubBlockOutcome::Unreadable(err.to_string());
        }
    };

    scrub_inline_content_bytes(&bytes)
}

fn scrub_inline_content_bytes(bytes: &[u8]) -> ScrubBlockOutcome {
    let (body, stored_checksum) = match split_inline_checksum(bytes) {
        Ok(parts) => parts,
        Err(err) => return ScrubBlockOutcome::Unreadable(err.to_string()),
    };
    if let Some(expected) = stored_checksum {
        let actual = checksum64(body);
        if actual != expected {
            return ScrubBlockOutcome::Corrupt { expected, actual };
        }
    }

    match decode_content(bytes) {
        Ok(_) => ScrubBlockOutcome::Clean,
        Err(err) => ScrubBlockOutcome::Unreadable(err.to_string()),
    }
}
pub(crate) fn scrub_inodes_content(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
) -> Result<ScrubReport> {
    let mut report = ScrubReport::empty();

    for (inode_id, record) in inodes {
        if record.size == 0 || !record.is_file_like() {
            continue;
        }

        // Determine content layout
        let layout = match read_content_layout_from_store(store, *inode_id, record, true) {
            Ok(layout) => layout,
            Err(err) => {
                report.blocks_unreadable += 1;
                report.violations.push(ScrubViolation {
                    block_id: ScrubBlockId {
                        inode_id: inode_id.get(),
                        data_version: record.data_version,
                        kind: ScrubBlockKind::InlineContent,
                    },
                    key_hex: content_object_key_for_version(*inode_id, record.data_version)
                        .short_hex(),
                    outcome: ScrubBlockOutcome::Unreadable(err.to_string()),
                });
                continue;
            }
        };

        match layout {
            ContentLayout::Inline(_) => {
                report.blocks_scanned += 1;
                let outcome = scrub_inline_content(store, *inode_id, record);
                match &outcome {
                    ScrubBlockOutcome::Clean => report.blocks_clean += 1,
                    ScrubBlockOutcome::Corrupt { .. } => {
                        report.blocks_corrupt += 1;
                        report.violations.push(ScrubViolation {
                            block_id: ScrubBlockId {
                                inode_id: inode_id.get(),
                                data_version: record.data_version,
                                kind: ScrubBlockKind::InlineContent,
                            },
                            key_hex: content_object_key_for_version(*inode_id, record.data_version)
                                .short_hex(),
                            outcome,
                        });
                    }
                    ScrubBlockOutcome::Unreadable(_) => {
                        report.blocks_unreadable += 1;
                        report.violations.push(ScrubViolation {
                            block_id: ScrubBlockId {
                                inode_id: inode_id.get(),
                                data_version: record.data_version,
                                kind: ScrubBlockKind::InlineContent,
                            },
                            key_hex: content_object_key_for_version(*inode_id, record.data_version)
                                .short_hex(),
                            outcome,
                        });
                    }
                    ScrubBlockOutcome::NoChecksum => {
                        report.blocks_no_checksum += 1;
                    }
                }
            }
            ContentLayout::Chunked(manifest) => {
                report.blocks_scanned += 1; // manifest
                report.blocks_clean += 1; // manifest is clean if parsed successfully

                for chunk_ref in &manifest.chunks {
                    report.blocks_scanned += 1;
                    let outcome = scrub_content_chunk(store, *inode_id, chunk_ref);
                    match &outcome {
                        ScrubBlockOutcome::Clean => report.blocks_clean += 1,
                        ScrubBlockOutcome::Corrupt { .. } => {
                            report.blocks_corrupt += 1;
                            report.violations.push(ScrubViolation {
                                block_id: ScrubBlockId {
                                    inode_id: inode_id.get(),
                                    data_version: chunk_ref.data_version,
                                    kind: ScrubBlockKind::ContentChunk {
                                        chunk_index: chunk_ref.chunk_index,
                                    },
                                },
                                key_hex: content_chunk_object_key_for_version(
                                    *inode_id,
                                    chunk_ref.data_version,
                                    chunk_ref.chunk_index,
                                )
                                .short_hex(),
                                outcome,
                            });
                        }
                        ScrubBlockOutcome::Unreadable(_) => {
                            report.blocks_unreadable += 1;
                            report.violations.push(ScrubViolation {
                                block_id: ScrubBlockId {
                                    inode_id: inode_id.get(),
                                    data_version: chunk_ref.data_version,
                                    kind: ScrubBlockKind::ContentChunk {
                                        chunk_index: chunk_ref.chunk_index,
                                    },
                                },
                                key_hex: content_chunk_object_key_for_version(
                                    *inode_id,
                                    chunk_ref.data_version,
                                    chunk_ref.chunk_index,
                                )
                                .short_hex(),
                                outcome,
                            });
                        }
                        ScrubBlockOutcome::NoChecksum => {
                            report.blocks_no_checksum += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(report)
}

// ── Resolver skeleton (PC-019B.3) ─────────────────────────────────────

/// Possible actions for resolving a corrupt block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairStrategy {
    /// Retry from a replica (not yet implemented — requires redundancy).
    Reconstruct,
    /// Mark the block as corrupt and return an error to the caller.
    MarkCorrupt,
    /// Truncate the file at the last known-good offset.
    Truncate,
}

#[cfg(test)]
/// Attempt to resolve a corrupt block violation.
///
/// Delegates to [`crate::repair::resolve_violation`] with default
/// resolver context (no redundancy). The caller may also use the
/// resolver directly when more context is available.
pub(crate) fn resolve_violation(violation: &ScrubViolation) -> RepairStrategy {
    crate::repair::resolve_violation(violation, crate::repair::ResolverContext::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::LocalFileSystem;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::StoreOptions;

    fn temp_fs() -> (std::path::PathBuf, LocalFileSystem) {
        let root = std::env::temp_dir().join(format!(
            "tidefs-scrub-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos(),
        ));
        assert!(!root.exists(), "stale temp dir at {root:?}");
        std::fs::create_dir_all(&root).expect("create temp dir");
        let fs = LocalFileSystem::open_with_options(&root, StoreOptions::default()).expect("open");
        (root, fs)
    }

    #[test]
    fn scrub_empty_filesystem_is_clean() {
        let (root, fs) = temp_fs();
        let _cleanup = Cleanup(Some(root));
        let report = scrub_inodes_content(fs.store_ref(), fs.inode_records()).expect("scrub");
        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 0);
        assert_eq!(report.blocks_clean, 0);
    }

    #[test]
    fn scrub_small_file_is_clean() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/test.txt", 0o644).expect("create");
        fs.write_file("/test.txt", 0, b"hello world")
            .expect("write");

        let inodes = fs.inode_records();
        eprintln!("inodes: {inodes:?}");
        let report = scrub_inodes_content(fs.store_ref(), inodes).expect("scrub");
        eprintln!(
            "report: blocks_scanned={} blocks_clean={} blocks_corrupt={} violations={:?}",
            report.blocks_scanned, report.blocks_clean, report.blocks_corrupt, report.violations
        );
        assert!(report.is_clean());
        assert!(report.blocks_scanned > 0);
        assert_eq!(report.blocks_corrupt, 0);
    }

    #[test]
    fn scrub_large_file_is_clean() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/big.bin", 0o644).expect("create");
        // Write enough data to span multiple chunks (chunk size = 2048)
        let data = vec![0xAB; 5000];
        fs.write_file("/big.bin", 0, &data).expect("write");

        let inodes = fs.inode_records();
        let report = scrub_inodes_content(fs.store_ref(), inodes).expect("scrub");
        assert!(report.is_clean());
        assert!(
            report.blocks_scanned > 1,
            "multi-chunk file should scan multiple blocks"
        );
        assert_eq!(report.blocks_corrupt, 0);
    }

    #[test]
    fn scrub_multiple_files() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/a.txt", 0o644).expect("create");
        fs.write_file("/a.txt", 0, b"file a").expect("write");
        fs.create_file("/b.txt", 0o644).expect("create");
        fs.write_file("/b.txt", 0, b"file b").expect("write");

        let inodes = fs.inode_records();
        let report = scrub_inodes_content(fs.store_ref(), inodes).expect("scrub");
        assert!(report.is_clean());
        assert!(report.blocks_scanned >= 2);
    }

    #[test]
    fn scrub_skips_empty_files() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/empty.txt", 0o644).expect("create");

        let inodes = fs.inode_records();
        let report = scrub_inodes_content(fs.store_ref(), inodes).expect("scrub");
        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 0);
    }

    #[test]
    fn scrub_report_empty_is_clean() {
        let report = ScrubReport::empty();
        assert!(report.is_clean());
        assert_eq!(report.blocks_scanned, 0);
    }

    #[test]
    fn scrub_inline_content_checksum_mismatch_reports_corrupt() {
        use crate::encoding::encode_content;
        use crate::types::InodeRecord;
        use std::collections::BTreeMap;
        use tidefs_types_vfs_core::{Generation, NodeKind};

        let inode = InodeRecord {
            dir_storage_kind: 0,
            inode_id: InodeId::new(7),
            generation: Generation(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size: 11,
            data_version: 3,
            metadata_version: 3,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            rdev: 0,
        };

        let mut bytes = encode_content(&inode, b"hello world");
        bytes[36] ^= 0xFF;

        match scrub_inline_content_bytes(&bytes) {
            ScrubBlockOutcome::Corrupt { expected, actual } => assert_ne!(expected, actual),
            other => panic!("expected corrupt inline content, got {other:?}"),
        }
    }

    /// RAII guard that removes a directory on drop.
    struct Cleanup<P: AsRef<std::path::Path>>(Option<P>);
    impl<P: AsRef<std::path::Path>> Drop for Cleanup<P> {
        fn drop(&mut self) {
            if let Some(ref p) = self.0 {
                let _ = std::fs::remove_dir_all(p);
            }
        }
    }

    #[test]
    fn scrub_block_id_ordering() {
        let a = ScrubBlockId {
            inode_id: 1,
            data_version: 5,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
        };
        let b = ScrubBlockId {
            inode_id: 1,
            data_version: 5,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 1 },
        };
        assert!(a < b);
    }

    #[test]
    fn resolve_violation_returns_mark_corrupt() {
        let violation = ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 42,
                data_version: 3,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
            },
            key_hex: "deadbeef".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xAAAA),
                actual: IntegrityDigest64(0xBBBB),
            },
        };
        assert_eq!(resolve_violation(&violation), RepairStrategy::MarkCorrupt);
    }

    #[test]
    fn scrub_content_chunk_clean() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/test.bin", 0o644).expect("create");
        let data = vec![0xCD; 4096]; // 2 chunks
        fs.write_file("/test.bin", 0, &data).expect("write");

        // Read back through scrub
        let inodes = fs.inode_records();
        let report = scrub_inodes_content(fs.store_ref(), inodes).expect("scrub");
        assert!(report.is_clean());
        assert_eq!(report.blocks_corrupt, 0);
    }

    #[test]
    fn scrub_handles_missing_key_gracefully() {
        let (_root, fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        // Create a chunk ref pointing to a key that doesn't exist
        let chunk_ref = ContentChunkRef {
            chunk_index: 0,
            data_version: 1,
            len: 100,
            checksum: IntegrityDigest64(0),
            placement_receipt_generation: 0,
        };
        let outcome = scrub_content_chunk(fs.store_ref(), InodeId::new(999), &chunk_ref);
        match outcome {
            ScrubBlockOutcome::Unreadable(_) => {} // expected
            other => panic!("expected Unreadable, got {other:?}"),
        }
    }

    #[test]
    fn scrub_violation_carries_block_identity() {
        let violation = ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 7,
                data_version: 3,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 2 },
            },
            key_hex: "abcdef0123456789".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(100),
                actual: IntegrityDigest64(200),
            },
        };
        assert_eq!(violation.block_id.inode_id, 7);
        assert_eq!(violation.block_id.data_version, 3);
        assert_eq!(violation.key_hex, "abcdef0123456789");
    }
}
