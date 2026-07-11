// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scrub pipeline for block-level integrity verification.
//!
//! The scrub module walks local filesystem content blocks through the mounted
//! content scrub/read authority and reports checksum-layer evidence without
//! making lower-layer bytes the mounted repair identity.
//! It is consumed by the online verifier and reports corruptions that
//! the resolver tracked by #590 can attempt to repair.
//!
//! This module implements the scrub pipeline using the
//! `FastBlockChecksum` and `ProductionBlockChecksum` implementations
//! from the checksum authority tracked by #588.

use std::collections::BTreeMap;

#[cfg(test)]
use tidefs_local_object_store::checksum64;
use tidefs_local_object_store::{
    DeviceIoClass, IntegrityDigest64, LocalObjectStore, ObjectKey, Pool,
};
use tidefs_types_vfs_core::InodeId;

use crate::checksum::{BlockChecksum, FastBlockChecksum};
use crate::content::{
    read_mounted_content_scrub_block, validate_content_manifest, MountedContentScrubReadTarget,
};
use crate::encoding::{decode_content_manifest, split_inline_checksum};
use crate::object_keys::{content_chunk_object_key_for_version, content_object_key_for_version};
use crate::records::ContentChunkRef;
use crate::types::{
    InodeRecord, MountedContentChecksumEvidence, MountedContentChecksumLayer,
    MountedContentPlacementEvidence, MountedContentScrubRead, CONTENT_MANIFEST_MAGIC,
    CONTENT_MANIFEST_SPARSE_MAGIC,
};
pub(crate) use crate::types::{ScrubBlockId, ScrubBlockKind};
use crate::ContentManifestObject;
use crate::Result;

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

/// Mounted plaintext identity that a scrub result is reported against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScrubPlaintextIdentity {
    pub block_id: ScrubBlockId,
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up repair gating.
    pub expected_plaintext_len: u64,
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up repair gating.
    pub observed_plaintext_len: Option<u64>,
}

/// Raw/media diagnostic context attached to a scrub report entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScrubRawMediaDiagnostic {
    pub object_key_hex: Option<String>,
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up diagnostics.
    pub reason: Option<String>,
}

/// Evidence recorded for a scrubbed mounted content block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ScrubBlockEvidence {
    pub plaintext_identity: ScrubPlaintextIdentity,
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up repair gating.
    pub checksum_layer: Option<MountedContentChecksumEvidence>,
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up repair gating.
    pub placement_evidence: MountedContentPlacementEvidence,
    pub raw_media_diagnostic: ScrubRawMediaDiagnostic,
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
    #[allow(dead_code)] // INTENT: #651 scrub evidence consumed by follow-up repair gating.
    pub block_evidence: BTreeMap<ScrubBlockId, ScrubBlockEvidence>,
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
            block_evidence: BTreeMap::new(),
        }
    }

    pub(crate) fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }
}

// ── Scrub implementation ──────────────────────────────────────────────

#[derive(Clone, Debug)]
struct ScrubbedBlock {
    outcome: ScrubBlockOutcome,
    evidence: ScrubBlockEvidence,
}

/// Scrub a single content block through the mounted scrub/read authority.
#[allow(dead_code)] // INTENT: focused scrub helper retained for crate tests and repair consumers.
pub(crate) fn scrub_content_chunk(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    chunk_ref: &ContentChunkRef,
) -> ScrubBlockOutcome {
    scrub_content_chunk_with_pool(store, inode_id, record, chunk_ref, None).outcome
}

/// Scrub inline content through the mounted scrub/read authority.
#[allow(dead_code)] // INTENT: focused scrub helper retained for crate tests and repair consumers.
pub(crate) fn scrub_inline_content(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
) -> ScrubBlockOutcome {
    scrub_inline_content_with_pool(store, inode_id, record, None).outcome
}

fn scrub_inline_content_with_pool(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    pool: Option<&Pool>,
) -> ScrubbedBlock {
    let key = content_object_key_for_version(inode_id, record.data_version);
    scrub_mounted_content_target(
        store,
        inode_id,
        record,
        MountedContentScrubReadTarget::Inline,
        record.size,
        Some(key),
        pool,
        || inline_checksum_evidence(store, key),
    )
}

fn scrub_content_chunk_with_pool(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    chunk_ref: &ContentChunkRef,
    pool: Option<&Pool>,
) -> ScrubbedBlock {
    let key = if chunk_ref.is_hole() {
        None
    } else {
        Some(content_chunk_object_key_for_version(
            inode_id,
            chunk_ref.data_version,
            chunk_ref.chunk_index,
        ))
    };

    scrub_mounted_content_target(
        store,
        inode_id,
        record,
        MountedContentScrubReadTarget::ContentChunk(chunk_ref),
        u64::from(chunk_ref.len),
        key,
        pool,
        || chunk_checksum_evidence(store, key, chunk_ref),
    )
}

fn scrub_mounted_content_target<F>(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    target: MountedContentScrubReadTarget<'_>,
    expected_plaintext_len: u64,
    object_key: Option<ObjectKey>,
    pool: Option<&Pool>,
    checksum_evidence: F,
) -> ScrubbedBlock
where
    F: FnOnce() -> (Option<MountedContentChecksumEvidence>, Option<String>),
{
    match read_mounted_content_scrub_block(store, inode_id, record, target, pool) {
        Ok(read) => ScrubbedBlock {
            outcome: ScrubBlockOutcome::Clean,
            evidence: evidence_from_authority_read(read, expected_plaintext_len),
        },
        Err(err) => {
            let (checksum_layer, lower_reason) = checksum_evidence();
            let outcome = corrupt_outcome_from_checksum(&checksum_layer)
                .unwrap_or_else(|| ScrubBlockOutcome::Unreadable(err.to_string()));
            let mut reason = Some(err.to_string());
            if let Some(lower_reason) = lower_reason {
                reason = Some(format!("{err}; {lower_reason}"));
            }

            ScrubbedBlock {
                outcome,
                evidence: ScrubBlockEvidence {
                    plaintext_identity: ScrubPlaintextIdentity {
                        block_id: block_id_for_target(inode_id, record, target),
                        expected_plaintext_len,
                        observed_plaintext_len: None,
                    },
                    checksum_layer,
                    placement_evidence: placement_evidence_for_content_key(
                        pool,
                        object_key,
                        inode_id.get(),
                        expected_receipt_generation_for_target(target),
                    ),
                    raw_media_diagnostic: ScrubRawMediaDiagnostic {
                        object_key_hex: object_key.map(ObjectKey::short_hex),
                        reason,
                    },
                },
            }
        }
    }
}

fn evidence_from_authority_read(
    read: MountedContentScrubRead,
    expected_plaintext_len: u64,
) -> ScrubBlockEvidence {
    ScrubBlockEvidence {
        plaintext_identity: ScrubPlaintextIdentity {
            block_id: read.block_id,
            expected_plaintext_len,
            observed_plaintext_len: Some(read.plaintext_bytes.len() as u64),
        },
        checksum_layer: Some(read.checksum_evidence),
        placement_evidence: read.placement_evidence,
        raw_media_diagnostic: ScrubRawMediaDiagnostic {
            object_key_hex: read.object_key.map(ObjectKey::short_hex),
            reason: None,
        },
    }
}

fn corrupt_outcome_from_checksum(
    checksum_layer: &Option<MountedContentChecksumEvidence>,
) -> Option<ScrubBlockOutcome> {
    let checksum_layer = checksum_layer.as_ref()?;
    let expected = checksum_layer.expected?;
    if checksum_layer.actual == expected {
        return None;
    }
    Some(ScrubBlockOutcome::Corrupt {
        expected,
        actual: checksum_layer.actual,
    })
}

fn inline_checksum_evidence(
    store: &LocalObjectStore,
    key: ObjectKey,
) -> (Option<MountedContentChecksumEvidence>, Option<String>) {
    let encoded = match store.get(key) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => return (None, Some("inline content object not found".to_string())),
        Err(err) => return (None, Some(err.to_string())),
    };
    let (body, expected) = match split_inline_checksum(&encoded) {
        Ok(parts) => parts,
        Err(err) => return (None, Some(err.to_string())),
    };
    (
        Some(MountedContentChecksumEvidence {
            layer: MountedContentChecksumLayer::InlineContentBody,
            expected,
            actual: FastBlockChecksum::compute(body),
            encoded_len: body.len() as u64,
        }),
        None,
    )
}

fn chunk_checksum_evidence(
    store: &LocalObjectStore,
    key: Option<ObjectKey>,
    chunk_ref: &ContentChunkRef,
) -> (Option<MountedContentChecksumEvidence>, Option<String>) {
    let Some(key) = key else {
        return (
            Some(MountedContentChecksumEvidence {
                layer: MountedContentChecksumLayer::SparseHole,
                expected: Some(IntegrityDigest64(0)),
                actual: IntegrityDigest64(0),
                encoded_len: 0,
            }),
            None,
        );
    };
    let encoded = match store.get(key) {
        Ok(Some(encoded)) => encoded,
        Ok(None) => return (None, Some("content chunk object not found".to_string())),
        Err(err) => return (None, Some(err.to_string())),
    };
    (
        Some(MountedContentChecksumEvidence {
            layer: MountedContentChecksumLayer::EncodedContentChunk,
            expected: Some(chunk_ref.checksum),
            actual: FastBlockChecksum::compute(&encoded),
            encoded_len: encoded.len() as u64,
        }),
        None,
    )
}

fn block_id_for_target(
    inode_id: InodeId,
    record: &InodeRecord,
    target: MountedContentScrubReadTarget<'_>,
) -> ScrubBlockId {
    match target {
        MountedContentScrubReadTarget::Inline => ScrubBlockId {
            inode_id: inode_id.get(),
            data_version: record.data_version,
            kind: ScrubBlockKind::InlineContent,
        },
        MountedContentScrubReadTarget::ContentChunk(chunk_ref) => ScrubBlockId {
            inode_id: inode_id.get(),
            data_version: chunk_ref.data_version,
            kind: ScrubBlockKind::ContentChunk {
                chunk_index: chunk_ref.chunk_index,
            },
        },
    }
}

fn expected_receipt_generation_for_target(
    target: MountedContentScrubReadTarget<'_>,
) -> Option<u64> {
    match target {
        MountedContentScrubReadTarget::Inline => None,
        MountedContentScrubReadTarget::ContentChunk(chunk_ref) => {
            nonzero_receipt_generation(chunk_ref.placement_receipt_generation)
        }
    }
}

fn read_content_manifest_for_scrub(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
) -> Result<Option<ContentManifestObject>> {
    let key = content_object_key_for_version(inode_id, record.data_version);
    let Some(bytes) = store.get(key)? else {
        return Ok(None);
    };
    if !bytes.starts_with(&CONTENT_MANIFEST_MAGIC)
        && !bytes.starts_with(&CONTENT_MANIFEST_SPARSE_MAGIC)
    {
        return Ok(None);
    }

    let manifest = decode_content_manifest(&bytes)?;
    validate_content_manifest(inode_id, record, &manifest)?;
    Ok(Some(manifest))
}

fn manifest_error_scrubbed_block(
    inode_id: InodeId,
    record: &InodeRecord,
    pool: Option<&Pool>,
    reason: String,
) -> ScrubbedBlock {
    let key = content_object_key_for_version(inode_id, record.data_version);
    ScrubbedBlock {
        outcome: ScrubBlockOutcome::Unreadable(reason.clone()),
        evidence: ScrubBlockEvidence {
            plaintext_identity: ScrubPlaintextIdentity {
                block_id: ScrubBlockId {
                    inode_id: inode_id.get(),
                    data_version: record.data_version,
                    kind: ScrubBlockKind::ContentManifest,
                },
                expected_plaintext_len: record.size,
                observed_plaintext_len: None,
            },
            checksum_layer: None,
            placement_evidence: placement_evidence_for_content_key(
                pool,
                Some(key),
                inode_id.get(),
                None,
            ),
            raw_media_diagnostic: ScrubRawMediaDiagnostic {
                object_key_hex: Some(key.short_hex()),
                reason: Some(reason),
            },
        },
    }
}

fn nonzero_receipt_generation(generation: u64) -> Option<u64> {
    if generation == 0 {
        None
    } else {
        Some(generation)
    }
}

fn placement_evidence_for_content_key(
    pool: Option<&Pool>,
    key: Option<ObjectKey>,
    subject_id: u64,
    expected_generation: Option<u64>,
) -> MountedContentPlacementEvidence {
    let Some(key) = key else {
        return MountedContentPlacementEvidence::SparseHole;
    };
    let Some(pool) = pool else {
        return match expected_generation {
            Some(expected_generation) => MountedContentPlacementEvidence::ReceiptUnavailable {
                expected_generation: Some(expected_generation),
            },
            None => MountedContentPlacementEvidence::ReceiptMissing {
                expected_generation: None,
            },
        };
    };

    match pool.placement_receipt_for_key(DeviceIoClass::Data, key) {
        Ok(Some(receipt)) => match expected_generation {
            Some(expected_generation) if receipt.generation == expected_generation => {
                match receipt.shared_receipt_ref_for_subject(subject_id) {
                    Ok(placement_receipt_ref) => MountedContentPlacementEvidence::ReceiptVerified {
                        generation: expected_generation,
                        placement_receipt_ref,
                    },
                    Err(_) => MountedContentPlacementEvidence::ReceiptUnavailable {
                        expected_generation: Some(expected_generation),
                    },
                }
            }
            Some(expected_generation) => MountedContentPlacementEvidence::ReceiptStale {
                expected_generation,
                observed_generation: receipt.generation,
            },
            None => MountedContentPlacementEvidence::ReceiptObservedButUnbound {
                generation: receipt.generation,
            },
        },
        Ok(None) => MountedContentPlacementEvidence::ReceiptMissing {
            expected_generation,
        },
        Err(_) => MountedContentPlacementEvidence::ReceiptUnavailable {
            expected_generation,
        },
    }
}

#[cfg(test)]
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

    ScrubBlockOutcome::Clean
}

fn record_scrubbed_block(report: &mut ScrubReport, scrubbed: ScrubbedBlock) {
    let block_id = scrubbed.evidence.plaintext_identity.block_id.clone();
    let key_hex = scrubbed
        .evidence
        .raw_media_diagnostic
        .object_key_hex
        .clone()
        .unwrap_or_else(|| "sparse-hole".to_string());
    report
        .block_evidence
        .insert(block_id.clone(), scrubbed.evidence);

    match scrubbed.outcome {
        ScrubBlockOutcome::Clean => report.blocks_clean += 1,
        outcome @ ScrubBlockOutcome::Corrupt { .. } => {
            report.blocks_corrupt += 1;
            report.violations.push(ScrubViolation {
                block_id,
                key_hex,
                outcome,
            });
        }
        outcome @ ScrubBlockOutcome::Unreadable(_) => {
            report.blocks_unreadable += 1;
            report.violations.push(ScrubViolation {
                block_id,
                key_hex,
                outcome,
            });
        }
        ScrubBlockOutcome::NoChecksum => {
            report.blocks_no_checksum += 1;
        }
    }
}

pub(crate) fn scrub_inodes_content(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
) -> Result<ScrubReport> {
    scrub_inodes_content_with_pool(store, inodes, None)
}

#[allow(dead_code)] // INTENT: #651 pool-aware evidence path consumed by follow-up repair gating.
pub(crate) fn scrub_inodes_content_with_pool(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    pool: Option<&Pool>,
) -> Result<ScrubReport> {
    let mut report = ScrubReport::empty();

    for (inode_id, record) in inodes {
        if record.size == 0 || !record.is_file_like() {
            continue;
        }

        let inline_scrubbed = scrub_inline_content_with_pool(store, *inode_id, record, pool);
        if matches!(inline_scrubbed.outcome, ScrubBlockOutcome::Clean) {
            report.blocks_scanned += 1;
            record_scrubbed_block(&mut report, inline_scrubbed);
            continue;
        }

        match read_content_manifest_for_scrub(store, *inode_id, record) {
            Ok(Some(manifest)) => {
                report.blocks_scanned += 1; // manifest
                report.blocks_clean += 1; // manifest is clean if parsed successfully

                for chunk_ref in &manifest.chunks {
                    report.blocks_scanned += 1;
                    record_scrubbed_block(
                        &mut report,
                        scrub_content_chunk_with_pool(store, *inode_id, record, chunk_ref, pool),
                    );
                }
            }
            Ok(None) => {
                report.blocks_scanned += 1;
                record_scrubbed_block(&mut report, inline_scrubbed);
            }
            Err(err) => {
                report.blocks_scanned += 1;
                record_scrubbed_block(
                    &mut report,
                    manifest_error_scrubbed_block(*inode_id, record, pool, err.to_string()),
                );
            }
        }
    }

    Ok(report)
}

// ── Resolver skeleton ─────────────────────────────────────────────────

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

    use crate::encoding::encode_content_chunk;
    use crate::object_keys::content_chunk_object_key_for_version;
    use crate::types::ContentCompressionPolicy;
    use crate::LocalFileSystem;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::pool::{PoolConfig, PoolProperties};
    use tidefs_local_object_store::{
        DeviceBacking, DeviceClass, DeviceConfig, DeviceKind, StoreOptions,
    };
    use tidefs_types_vfs_core::{Generation, NodeKind};

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

    fn temp_pool(label: &str) -> Pool {
        let root = std::env::temp_dir().join(format!(
            "tidefs-scrub-pool-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        let data_dir = root.join("data");
        Pool::create(
            PoolConfig {
                name: "scrub-test-pool".into(),
                root_path: root,
                devices: vec![DeviceConfig {
                    media_class: Default::default(),
                    path: data_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data_dir },
                    encryption: None,
                    compression: None,
                }],
            },
            PoolProperties::default(),
            &StoreOptions::test_fast(),
        )
        .expect("create temp pool")
    }

    fn test_file_record(inode_id: u64, data_version: u64, size: u64) -> InodeRecord {
        InodeRecord {
            dir_storage_kind: 0,
            inode_id: InodeId::new(inode_id),
            generation: Generation(1),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version,
            metadata_version: data_version,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattr_storage_kind: 0,
            xattrs: BTreeMap::new(),
            dir_rev: 0,
            subtree_rev: 0,
            rdev: 0,
        }
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
        let chunk_evidence = report
            .block_evidence
            .values()
            .find(|entry| {
                matches!(
                    entry.plaintext_identity.block_id.kind,
                    ScrubBlockKind::ContentChunk { .. }
                )
            })
            .expect("chunk evidence");
        assert_eq!(
            chunk_evidence
                .checksum_layer
                .as_ref()
                .map(|entry| entry.layer),
            Some(MountedContentChecksumLayer::EncodedContentChunk)
        );
        assert!(chunk_evidence.raw_media_diagnostic.reason.is_none());
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
    fn scrub_report_records_inline_plaintext_and_checksum_evidence() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/inline.txt", 0o644).expect("create");
        fs.write_file("/inline.txt", 0, b"inline scrub evidence")
            .expect("write");

        let report = scrub_inodes_content(fs.store_ref(), fs.inode_records()).expect("scrub");
        let evidence = report
            .block_evidence
            .values()
            .find(|entry| {
                matches!(
                    entry.plaintext_identity.block_id.kind,
                    ScrubBlockKind::InlineContent
                )
            })
            .expect("inline evidence");

        assert_eq!(evidence.plaintext_identity.expected_plaintext_len, 21);
        assert_eq!(evidence.plaintext_identity.observed_plaintext_len, Some(21));
        assert_eq!(
            evidence.checksum_layer.as_ref().map(|entry| entry.layer),
            Some(MountedContentChecksumLayer::InlineContentBody)
        );
        assert!(evidence
            .checksum_layer
            .as_ref()
            .expect("checksum evidence")
            .matches_expected());
        assert_eq!(
            evidence.placement_evidence,
            MountedContentPlacementEvidence::ReceiptMissing {
                expected_generation: None
            }
        );
        assert!(evidence.raw_media_diagnostic.object_key_hex.is_some());
        assert!(evidence.raw_media_diagnostic.reason.is_none());
    }

    #[test]
    fn scrub_chunk_evidence_records_stale_receipt_without_repair_dispatch() {
        let mut pool = temp_pool("stale-receipt");
        let payload = b"chunk plaintext evidence".to_vec();
        let record = test_file_record(17, 4, payload.len() as u64);
        let key = content_chunk_object_key_for_version(record.inode_id, record.data_version, 0);
        let encoded = encode_content_chunk(&record, 0, &payload, &ContentCompressionPolicy::off());
        let checksum = FastBlockChecksum::compute(&encoded);
        let (_, receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, key, &encoded)
            .expect("write chunk through pool");
        let chunk_ref = ContentChunkRef {
            chunk_index: 0,
            data_version: record.data_version,
            len: payload.len() as u32,
            checksum,
            placement_receipt_generation: receipt.generation.saturating_add(1),
        };

        let scrubbed = scrub_content_chunk_with_pool(
            pool.raw_primary_store(),
            record.inode_id,
            &record,
            &chunk_ref,
            Some(&pool),
        );

        assert!(matches!(scrubbed.outcome, ScrubBlockOutcome::Clean));
        assert_eq!(
            scrubbed.evidence.plaintext_identity.block_id,
            ScrubBlockId {
                inode_id: record.inode_id.get(),
                data_version: record.data_version,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
            }
        );
        assert_eq!(
            scrubbed
                .evidence
                .checksum_layer
                .as_ref()
                .map(|entry| entry.layer),
            Some(MountedContentChecksumLayer::EncodedContentChunk)
        );
        assert_eq!(
            scrubbed.evidence.placement_evidence,
            MountedContentPlacementEvidence::ReceiptStale {
                expected_generation: receipt.generation.saturating_add(1),
                observed_generation: receipt.generation,
            }
        );
        assert!(!scrubbed
            .evidence
            .placement_evidence
            .allows_repair_dispatch());
    }

    #[test]
    fn scrub_inline_content_checksum_mismatch_reports_corrupt() {
        use crate::encoding::encode_content;
        let inode = test_file_record(7, 3, 11);

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
        let record = test_file_record(999, 1, 100);
        let outcome = scrub_content_chunk(fs.store_ref(), record.inode_id, &record, &chunk_ref);
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
