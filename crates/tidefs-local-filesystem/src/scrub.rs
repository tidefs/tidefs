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
use tidefs_local_object_store::pool::{
    ReplicatedReceiptEvidence, ReplicatedTargetEvidence, ReplicatedTargetReadOutcome,
};
use tidefs_local_object_store::{
    DeviceIoClass, IntegrityDigest64, LocalObjectStore, ObjectKey, Pool,
};
use tidefs_types_vfs_core::InodeId;

use crate::checksum::{BlockChecksum, FastBlockChecksum};
use crate::content::{
    read_mounted_content_scrub_block_in_keyspace, validate_content_manifest,
    MountedContentScrubReadTarget,
};
use crate::encoding::{decode_content_manifest, split_inline_checksum};
use crate::object_keys::FilesystemObjectKeyspace;
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

/// Mounted-checksum outcome for one exact target of the current local Pool
/// receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedRepairTargetChecksumOutcome {
    Clean {
        checksum: IntegrityDigest64,
    },
    Mismatch {
        expected: IntegrityDigest64,
        actual: IntegrityDigest64,
    },
    /// Bytes are readable and satisfy the mounted checksum, but fail the
    /// current placement receipt's physical payload digest.
    ReceiptMismatch {
        checksum: IntegrityDigest64,
    },
    Missing,
    Unreadable,
    NoChecksum,
}

/// Deterministic mounted-checksum evidence for one local receipt target.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedRepairTargetOutcome {
    pub device_index: u32,
    pub outcome: MountedRepairTargetChecksumOutcome,
}

/// Local two-target classification used by the mounted Pool repair carrier.
///
/// These identities are Pool device indices from the exact current placement
/// receipt. They are not distributed membership node ids or membership
/// epochs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MountedRepairClassification {
    CleanAgreement,
    SingleReplicaCorruption {
        corrupt_target: u32,
        clean_sources: Vec<u32>,
    },
    IncompleteComparison {
        missing_targets: Vec<u32>,
    },
    ReceiptTargetDisagreement,
    ChecksumAuthorityDisagreement,
    MissingChecksumEvidence {
        targets_without_checksum: Vec<u32>,
    },
}

/// Receipt- and checksum-bound comparison for one mounted repair candidate.
///
/// The Pool evidence retains physical BLAKE3 identity while
/// `target_outcomes` records the mounted checksum layer. Neither authority
/// substitutes for the other.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct MountedReplicatedRepairComparison {
    pub block_id: ScrubBlockId,
    pub object_key: ObjectKey,
    pub receipt_evidence: ReplicatedReceiptEvidence,
    pub checksum_layer: MountedContentChecksumLayer,
    pub target_outcomes: Vec<MountedRepairTargetOutcome>,
    pub classification: MountedRepairClassification,
}

#[derive(Clone, Debug)]
pub(crate) struct MountedRepairPlanningError {
    pub code: &'static str,
    pub message: String,
    pub object_key: Option<ObjectKey>,
    pub embedded_receipt_generation: Option<u64>,
}

impl MountedRepairPlanningError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            object_key: None,
            embedded_receipt_generation: None,
        }
    }

    fn with_receipt_context(mut self, object_key: ObjectKey, generation: u64) -> Self {
        self.object_key = Some(object_key);
        self.embedded_receipt_generation = Some(generation);
        self
    }
}

fn target_mounted_read_outcome(
    kind: ScrubBlockKind,
    target: &ReplicatedTargetEvidence,
    expected: Option<IntegrityDigest64>,
) -> MountedRepairTargetChecksumOutcome {
    match &target.outcome {
        ReplicatedTargetReadOutcome::Missing => {
            return MountedRepairTargetChecksumOutcome::Missing;
        }
        ReplicatedTargetReadOutcome::Unreadable => {
            return MountedRepairTargetChecksumOutcome::Unreadable;
        }
        ReplicatedTargetReadOutcome::Clean | ReplicatedTargetReadOutcome::Corrupt { .. } => {}
    }

    let Some(payload) = target.payload() else {
        return MountedRepairTargetChecksumOutcome::Unreadable;
    };
    let actual = match kind {
        ScrubBlockKind::InlineContent => match split_inline_checksum(payload) {
            Ok((body, Some(_))) => FastBlockChecksum::compute(body),
            Ok((_body, None)) => return MountedRepairTargetChecksumOutcome::NoChecksum,
            Err(_) => return MountedRepairTargetChecksumOutcome::Unreadable,
        },
        ScrubBlockKind::ContentChunk { .. } => FastBlockChecksum::compute(payload),
        ScrubBlockKind::ContentManifest => return MountedRepairTargetChecksumOutcome::NoChecksum,
    };
    let Some(expected) = expected else {
        return MountedRepairTargetChecksumOutcome::NoChecksum;
    };

    if actual != expected {
        MountedRepairTargetChecksumOutcome::Mismatch { expected, actual }
    } else if matches!(&target.outcome, ReplicatedTargetReadOutcome::Corrupt { .. }) {
        MountedRepairTargetChecksumOutcome::ReceiptMismatch { checksum: actual }
    } else {
        MountedRepairTargetChecksumOutcome::Clean { checksum: actual }
    }
}

fn classify_mounted_repair_targets(
    target_outcomes: &[MountedRepairTargetOutcome],
) -> MountedRepairClassification {
    debug_assert_eq!(target_outcomes.len(), 2);

    let missing_targets = target_outcomes
        .iter()
        .filter(|target| matches!(&target.outcome, MountedRepairTargetChecksumOutcome::Missing))
        .map(|target| target.device_index)
        .collect::<Vec<_>>();
    if !missing_targets.is_empty() {
        return MountedRepairClassification::IncompleteComparison { missing_targets };
    }

    let targets_without_checksum = target_outcomes
        .iter()
        .filter(|target| {
            matches!(
                &target.outcome,
                MountedRepairTargetChecksumOutcome::NoChecksum
            )
        })
        .map(|target| target.device_index)
        .collect::<Vec<_>>();
    if !targets_without_checksum.is_empty() {
        return MountedRepairClassification::MissingChecksumEvidence {
            targets_without_checksum,
        };
    }

    let clean_sources = target_outcomes
        .iter()
        .filter(|target| {
            matches!(
                &target.outcome,
                MountedRepairTargetChecksumOutcome::Clean { .. }
            )
        })
        .map(|target| target.device_index)
        .collect::<Vec<_>>();
    let corrupt_targets = target_outcomes
        .iter()
        .filter(|target| {
            matches!(
                &target.outcome,
                MountedRepairTargetChecksumOutcome::Mismatch { .. }
                    | MountedRepairTargetChecksumOutcome::ReceiptMismatch { .. }
                    | MountedRepairTargetChecksumOutcome::Unreadable
            )
        })
        .map(|target| target.device_index)
        .collect::<Vec<_>>();

    if clean_sources.len() == 2 {
        return MountedRepairClassification::CleanAgreement;
    }
    if let ([clean_source], [corrupt_target]) =
        (clean_sources.as_slice(), corrupt_targets.as_slice())
    {
        return MountedRepairClassification::SingleReplicaCorruption {
            corrupt_target: *corrupt_target,
            clean_sources: vec![*clean_source],
        };
    }

    if corrupt_targets.len() == 2 {
        let mismatch_actuals = target_outcomes
            .iter()
            .filter_map(|target| match &target.outcome {
                MountedRepairTargetChecksumOutcome::Mismatch { actual, .. } => Some(*actual),
                _ => None,
            })
            .collect::<Vec<_>>();
        if mismatch_actuals.len() == 2 && mismatch_actuals[0] == mismatch_actuals[1] {
            return MountedRepairClassification::ChecksumAuthorityDisagreement;
        }
    }

    MountedRepairClassification::ReceiptTargetDisagreement
}

/// Compare every target of one current two-copy receipt at the mounted
/// checksum layer for the exact scrub finding named by `block_id`.
///
/// All current devices are owned by this local Pool owner. Target identity and
/// ordering come only from the exact current receipt. Classification never
/// changes that order and never manufactures distributed membership evidence.
pub(crate) fn compare_mounted_replicated_repair(
    pool: &Pool,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    keyspace: FilesystemObjectKeyspace,
    block_id: &ScrubBlockId,
) -> std::result::Result<MountedReplicatedRepairComparison, MountedRepairPlanningError> {
    let inode_id = InodeId::new(block_id.inode_id);
    let record = inodes.get(&inode_id).ok_or_else(|| {
        MountedRepairPlanningError::new(
            "missing-current-inode",
            format!(
                "mounted repair inode {} is no longer current",
                block_id.inode_id
            ),
        )
    })?;

    let (object_key, checksum_layer, expected_checksum, expected_receipt_generation) =
        match block_id.kind {
            ScrubBlockKind::InlineContent => {
                return Err(MountedRepairPlanningError::new(
                    "unsupported-inline-content-repair",
                    "mounted inline-content repair has no crash-safe receipt/root reconciliation path",
                ));
            }
            ScrubBlockKind::ContentChunk { chunk_index } => {
                let manifest = read_content_manifest_for_scrub(
                    pool.raw_primary_store(),
                    inode_id,
                    record,
                    Some(pool),
                    keyspace,
                )
                .map_err(|error| {
                    MountedRepairPlanningError::new(
                        "content-manifest-unavailable",
                        format!("mounted repair could not read current content manifest: {error}"),
                    )
                })?
                .ok_or_else(|| {
                    MountedRepairPlanningError::new(
                        "content-layout-changed",
                        "mounted repair finding no longer names chunked content",
                    )
                })?;
                let chunk = manifest
                    .chunks
                    .iter()
                    .find(|chunk| {
                        chunk.chunk_index == chunk_index
                            && chunk.data_version == block_id.data_version
                            && !chunk.is_hole()
                    })
                    .ok_or_else(|| {
                        MountedRepairPlanningError::new(
                            "stale-content-generation",
                            "mounted content chunk identity changed after scrub",
                        )
                    })?;
                if chunk.placement_receipt_generation == 0 {
                    return Err(MountedRepairPlanningError::new(
                        "missing-content-receipt-generation",
                        "mounted content chunk manifest has no placement receipt generation",
                    ));
                }
                (
                    keyspace.content_chunk(inode_id, chunk.data_version, chunk.chunk_index),
                    MountedContentChecksumLayer::EncodedContentChunk,
                    Some(chunk.checksum),
                    Some(chunk.placement_receipt_generation),
                )
            }
            ScrubBlockKind::ContentManifest => {
                return Err(MountedRepairPlanningError::new(
                    "unsupported-content-manifest-repair",
                    "mounted content-manifest repair has no current checksum-layer mapping",
                ));
            }
        };

    let receipt_evidence = pool
        .replicated_receipt_evidence(DeviceIoClass::Data, object_key)
        .map_err(|error| {
            MountedRepairPlanningError::new(
                "receipt-evidence-refused",
                format!("mounted repair could not establish current receipt evidence: {error}"),
            )
        })?
        .ok_or_else(|| {
            MountedRepairPlanningError::new(
                "missing-current-receipt",
                "mounted repair candidate has no current placement receipt",
            )
        })?;
    let receipt = &receipt_evidence.receipt;
    if let Some(expected_generation) = expected_receipt_generation {
        if expected_generation != receipt.generation {
            return Err(MountedRepairPlanningError::new(
                    "stale-content-receipt-generation",
                    format!(
                        "mounted content chunk manifest receipt generation {expected_generation} does not match current Pool receipt generation {}",
                        receipt.generation
                    ),
                )
                .with_receipt_context(object_key, expected_generation));
        }
    }
    if receipt.object_key != object_key
        || receipt.policy
            != (tidefs_local_object_store::PoolRedundancyPolicy::Replicated { copies: 2 })
        || receipt.targets.len() != 2
        || receipt_evidence.targets.len() != 2
    {
        return Err(MountedRepairPlanningError::new(
            "invalid-current-receipt-evidence",
            "mounted repair requires one exact current two-copy Pool receipt and both target outcomes",
        ));
    }

    let mut receipt_target_ids = receipt
        .targets
        .iter()
        .map(|target| target.device_index)
        .collect::<Vec<_>>();
    receipt_target_ids.sort_unstable();
    let mut evidence_target_ids = receipt_evidence
        .targets
        .iter()
        .map(|target| target.target.device_index)
        .collect::<Vec<_>>();
    evidence_target_ids.sort_unstable();
    if receipt_target_ids[0] == receipt_target_ids[1]
        || evidence_target_ids[0] == evidence_target_ids[1]
        || evidence_target_ids != receipt_target_ids
    {
        return Err(MountedRepairPlanningError::new(
            "invalid-receipt-target-identities",
            "mounted repair receipt evidence does not name two distinct exact Pool targets",
        ));
    }

    let mut target_outcomes = receipt_evidence
        .targets
        .iter()
        .map(|target| MountedRepairTargetOutcome {
            device_index: target.target.device_index,
            outcome: target_mounted_read_outcome(block_id.kind, target, expected_checksum),
        })
        .collect::<Vec<_>>();
    target_outcomes.sort_by_key(|target| target.device_index);
    let classification = classify_mounted_repair_targets(&target_outcomes);

    Ok(MountedReplicatedRepairComparison {
        block_id: block_id.clone(),
        object_key,
        receipt_evidence,
        checksum_layer,
        target_outcomes,
        classification,
    })
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
    scrub_content_chunk_in_keyspace(
        store,
        inode_id,
        record,
        chunk_ref,
        FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
    )
}

pub(crate) fn scrub_content_chunk_in_keyspace(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    chunk_ref: &ContentChunkRef,
    keyspace: FilesystemObjectKeyspace,
) -> ScrubBlockOutcome {
    scrub_content_chunk_with_pool(store, inode_id, record, chunk_ref, None, keyspace).outcome
}

/// Scrub inline content through the mounted scrub/read authority.
#[allow(dead_code)] // INTENT: focused scrub helper retained for crate tests and repair consumers.
pub(crate) fn scrub_inline_content(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
) -> ScrubBlockOutcome {
    scrub_inline_content_with_pool(
        store,
        inode_id,
        record,
        None,
        FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
    )
    .outcome
}

fn scrub_inline_content_with_pool(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    pool: Option<&Pool>,
    keyspace: FilesystemObjectKeyspace,
) -> ScrubbedBlock {
    let key = keyspace.content(inode_id, record.data_version);
    scrub_mounted_content_target(
        store,
        inode_id,
        record,
        MountedContentScrubReadTarget::Inline,
        record.size,
        Some(key),
        pool,
        keyspace,
        || inline_checksum_evidence(store, key),
    )
}

fn scrub_content_chunk_with_pool(
    store: &LocalObjectStore,
    inode_id: InodeId,
    record: &InodeRecord,
    chunk_ref: &ContentChunkRef,
    pool: Option<&Pool>,
    keyspace: FilesystemObjectKeyspace,
) -> ScrubbedBlock {
    let key = if chunk_ref.is_hole() {
        None
    } else {
        Some(keyspace.content_chunk(inode_id, chunk_ref.data_version, chunk_ref.chunk_index))
    };

    scrub_mounted_content_target(
        store,
        inode_id,
        record,
        MountedContentScrubReadTarget::ContentChunk(chunk_ref),
        u64::from(chunk_ref.len),
        key,
        pool,
        keyspace,
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
    keyspace: FilesystemObjectKeyspace,
    checksum_evidence: F,
) -> ScrubbedBlock
where
    F: FnOnce() -> (Option<MountedContentChecksumEvidence>, Option<String>),
{
    match read_mounted_content_scrub_block_in_keyspace(
        store, inode_id, record, target, pool, keyspace,
    ) {
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
    pool: Option<&Pool>,
    keyspace: FilesystemObjectKeyspace,
) -> Result<Option<ContentManifestObject>> {
    let key = keyspace.content(inode_id, record.data_version);
    let bytes = match pool {
        Some(pool) => pool
            .get_with_current_receipt(DeviceIoClass::Data, key)?
            .map(|(bytes, _receipt)| bytes),
        None => store.get(key)?,
    };
    let Some(bytes) = bytes else {
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
    keyspace: FilesystemObjectKeyspace,
) -> ScrubbedBlock {
    let key = keyspace.content(inode_id, record.data_version);
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
    _subject_id: u64,
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
                #[cfg(feature = "distributed-repair")]
                match receipt.shared_receipt_ref_for_subject(_subject_id) {
                    Ok(placement_receipt_ref) => MountedContentPlacementEvidence::ReceiptVerified {
                        generation: expected_generation,
                        placement_receipt_ref,
                    },
                    Err(_) => MountedContentPlacementEvidence::ReceiptUnavailable {
                        expected_generation: Some(expected_generation),
                    },
                }
                #[cfg(not(feature = "distributed-repair"))]
                MountedContentPlacementEvidence::ReceiptObservedButUnbound {
                    generation: expected_generation,
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

#[allow(dead_code)] // INTENT: #651 pool-aware evidence path consumed by follow-up repair gating.
pub(crate) fn scrub_inodes_content_with_pool(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    pool: Option<&Pool>,
) -> Result<ScrubReport> {
    scrub_inodes_content_with_pool_in_keyspace(
        store,
        inodes,
        pool,
        FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
    )
}

pub(crate) fn scrub_inodes_content_with_pool_in_keyspace(
    store: &LocalObjectStore,
    inodes: &BTreeMap<InodeId, InodeRecord>,
    pool: Option<&Pool>,
    keyspace: FilesystemObjectKeyspace,
) -> Result<ScrubReport> {
    let mut report = ScrubReport::empty();

    for (inode_id, record) in inodes {
        if record.size == 0 || !record.is_file_like() {
            continue;
        }

        let inline_scrubbed =
            scrub_inline_content_with_pool(store, *inode_id, record, pool, keyspace);
        if matches!(inline_scrubbed.outcome, ScrubBlockOutcome::Clean) {
            report.blocks_scanned += 1;
            record_scrubbed_block(&mut report, inline_scrubbed);
            continue;
        }

        match read_content_manifest_for_scrub(store, *inode_id, record, pool, keyspace) {
            Ok(Some(manifest)) => {
                report.blocks_scanned += 1; // manifest
                report.blocks_clean += 1; // manifest is clean if parsed successfully

                for chunk_ref in &manifest.chunks {
                    report.blocks_scanned += 1;
                    record_scrubbed_block(
                        &mut report,
                        scrub_content_chunk_with_pool(
                            store, *inode_id, record, chunk_ref, pool, keyspace,
                        ),
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
                    manifest_error_scrubbed_block(
                        *inode_id,
                        record,
                        pool,
                        err.to_string(),
                        keyspace,
                    ),
                );
            }
        }
    }

    Ok(report)
}

// ── Resolver skeleton ─────────────────────────────────────────────────

/// Possible actions for resolving a corrupt block.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(any(test, feature = "distributed-repair"))]
pub enum RepairStrategy {
    /// Retry from a replica (not yet implemented — requires redundancy).
    #[cfg(feature = "distributed-repair")]
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

    use crate::encoding::{encode_content_chunk, encode_content_manifest};
    use crate::object_keys::content_chunk_object_key_for_version;
    use crate::types::ContentCompressionPolicy;
    use crate::LocalFileSystem;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tidefs_local_object_store::pool::{PoolConfig, PoolProperties, PoolRedundancyPolicy};
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

    fn temp_replicated_pool(label: &str) -> Pool {
        let root = std::env::temp_dir().join(format!(
            "tidefs-scrub-replicated-pool-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        let devices = (0..2)
            .map(|device_index| {
                let data_dir = root.join(format!("data-{device_index}"));
                DeviceConfig {
                    media_class: Default::default(),
                    path: data_dir.clone(),
                    backing: DeviceBacking::DirectoryObjectStoreCompat,
                    class: DeviceClass::Data,
                    kind: DeviceKind::Single { path: data_dir },
                    encryption: None,
                    compression: None,
                }
            })
            .collect();
        Pool::create(
            PoolConfig {
                name: "scrub-replicated-test-pool".into(),
                root_path: root,
                devices,
            },
            PoolProperties {
                redundancy_policy: PoolRedundancyPolicy::Replicated { copies: 2 },
                ..PoolProperties::default()
            },
            &StoreOptions::test_fast(),
        )
        .expect("create replicated temp pool")
    }

    struct RepairComparisonGenerationFixture {
        pool: Pool,
        inodes: BTreeMap<InodeId, InodeRecord>,
        keyspace: FilesystemObjectKeyspace,
        block_id: ScrubBlockId,
        manifest_key: ObjectKey,
        chunk_key: ObjectKey,
        embedded_generation: u64,
        current_generation: u64,
    }

    fn repair_comparison_generation_fixture(
        label: &str,
        embedded_generation: impl FnOnce(u64, u64) -> u64,
    ) -> RepairComparisonGenerationFixture {
        let mut pool = temp_replicated_pool(label);
        let payload = b"receipt-generation comparison fixture".to_vec();
        let record = test_file_record(27, 9, payload.len() as u64);
        let keyspace = FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID);
        let chunk_key = keyspace.content_chunk(record.inode_id, record.data_version, 0);
        let encoded = encode_content_chunk(&record, 0, &payload, &ContentCompressionPolicy::off())
            .expect("encode comparison chunk");
        let checksum = FastBlockChecksum::compute(&encoded);
        let (_, previous_receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, chunk_key, &encoded)
            .expect("write previous comparison chunk receipt");
        let (_, current_receipt) = pool
            .put_with_receipt(DeviceIoClass::Data, chunk_key, &encoded)
            .expect("rotate current comparison chunk receipt");
        assert!(
            current_receipt.generation > previous_receipt.generation,
            "fixture must retain a nonzero stale generation"
        );
        let embedded_generation =
            embedded_generation(previous_receipt.generation, current_receipt.generation);
        let manifest = ContentManifestObject {
            inode_id: record.inode_id,
            data_version: record.data_version,
            file_size: record.size,
            chunk_size: crate::content_chunk_size(),
            chunks: vec![ContentChunkRef {
                chunk_index: 0,
                data_version: record.data_version,
                len: payload.len() as u32,
                checksum,
                placement_receipt_generation: embedded_generation,
            }],
        };
        let manifest_key = keyspace.content(record.inode_id, record.data_version);
        pool.put_with_receipt(
            DeviceIoClass::Data,
            manifest_key,
            &encode_content_manifest(&manifest),
        )
        .expect("write comparison content manifest");
        let block_id = ScrubBlockId {
            inode_id: record.inode_id.get(),
            data_version: record.data_version,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
        };
        let inodes = BTreeMap::from([(record.inode_id, record)]);

        RepairComparisonGenerationFixture {
            pool,
            inodes,
            keyspace,
            block_id,
            manifest_key,
            chunk_key,
            embedded_generation,
            current_generation: current_receipt.generation,
        }
    }

    fn repair_comparison_refusal_without_mutation(
        fixture: &RepairComparisonGenerationFixture,
    ) -> MountedRepairPlanningError {
        let receipts_before = fixture
            .pool
            .placement_receipts(DeviceIoClass::Data)
            .expect("snapshot placement receipts before refusal");
        let manifest_before = fixture
            .pool
            .get_with_current_receipt(DeviceIoClass::Data, fixture.manifest_key)
            .expect("snapshot manifest before refusal");
        let chunk_before = fixture
            .pool
            .get_with_current_receipt(DeviceIoClass::Data, fixture.chunk_key)
            .expect("snapshot chunk before refusal");

        let error = compare_mounted_replicated_repair(
            &fixture.pool,
            &fixture.inodes,
            fixture.keyspace,
            &fixture.block_id,
        )
        .expect_err("receipt generation mismatch must refuse comparison planning");

        assert_eq!(
            fixture
                .pool
                .placement_receipts(DeviceIoClass::Data)
                .expect("read placement receipts after refusal"),
            receipts_before,
            "planning refusal must not rotate or replace Pool receipts"
        );
        assert_eq!(
            fixture
                .pool
                .get_with_current_receipt(DeviceIoClass::Data, fixture.manifest_key)
                .expect("read manifest after refusal"),
            manifest_before,
            "planning refusal must not rewrite the content manifest"
        );
        assert_eq!(
            fixture
                .pool
                .get_with_current_receipt(DeviceIoClass::Data, fixture.chunk_key)
                .expect("read chunk after refusal"),
            chunk_before,
            "planning refusal must not rewrite the content chunk"
        );
        error
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
    fn repair_comparison_refuses_missing_manifest_receipt_generation_without_mutation() {
        let fixture = repair_comparison_generation_fixture("missing-manifest-receipt", |_, _| 0);
        assert_eq!(fixture.embedded_generation, 0);

        let error = repair_comparison_refusal_without_mutation(&fixture);

        assert_eq!(error.code, "missing-content-receipt-generation");
        assert!(error
            .message
            .contains("has no placement receipt generation"));
    }

    #[test]
    fn repair_comparison_refuses_stale_manifest_receipt_generation_without_mutation() {
        let fixture = repair_comparison_generation_fixture(
            "stale-manifest-receipt",
            |previous_generation, _| previous_generation,
        );
        assert!(fixture.embedded_generation > 0);
        assert!(fixture.embedded_generation < fixture.current_generation);

        let error = repair_comparison_refusal_without_mutation(&fixture);

        assert_eq!(error.code, "stale-content-receipt-generation");
        assert!(error
            .message
            .contains(&fixture.embedded_generation.to_string()));
        assert!(error
            .message
            .contains(&fixture.current_generation.to_string()));
    }

    #[test]
    fn scrub_empty_filesystem_is_clean() {
        let (root, fs) = temp_fs();
        let _cleanup = Cleanup(Some(root));
        let report = fs.scrub_mounted_content_for_test().expect("scrub");
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
        fs.sync_all().expect("sync scrub test content");

        let inodes = fs.inode_records();
        let report = fs
            .scrub_mounted_content_records_for_test(inodes)
            .expect("scrub");
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
        fs.sync_all().expect("sync scrub test content");

        let inodes = fs.inode_records();
        let report = fs
            .scrub_mounted_content_records_for_test(inodes)
            .expect("scrub");
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
        fs.sync_all().expect("sync scrub test content");

        let inodes = fs.inode_records();
        let report = fs
            .scrub_mounted_content_records_for_test(inodes)
            .expect("scrub");
        assert!(report.is_clean());
        assert!(report.blocks_scanned >= 2);
    }

    #[test]
    fn scrub_skips_empty_files() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/empty.txt", 0o644).expect("create");

        let inodes = fs.inode_records();
        let report = fs
            .scrub_mounted_content_records_for_test(inodes)
            .expect("scrub");
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
    fn scrub_report_records_committed_plaintext_and_checksum_evidence() {
        let (_root, mut fs) = temp_fs();
        let _cleanup = Cleanup(Some(_root));
        fs.create_file("/committed.txt", 0o644).expect("create");
        fs.write_file("/committed.txt", 0, b"inline scrub evidence")
            .expect("write");
        fs.sync_all().expect("sync scrub test content");

        let report = fs.scrub_mounted_content_for_test().expect("scrub");
        let evidence = report
            .block_evidence
            .values()
            .find(|entry| {
                matches!(
                    entry.plaintext_identity.block_id.kind,
                    ScrubBlockKind::ContentChunk { chunk_index: 0 }
                )
            })
            .expect("committed content evidence");

        assert_eq!(evidence.plaintext_identity.expected_plaintext_len, 21);
        assert_eq!(evidence.plaintext_identity.observed_plaintext_len, Some(21));
        assert_eq!(
            evidence.checksum_layer.as_ref().map(|entry| entry.layer),
            Some(MountedContentChecksumLayer::EncodedContentChunk)
        );
        assert!(evidence
            .checksum_layer
            .as_ref()
            .expect("checksum evidence")
            .matches_expected());
        assert!(matches!(
            evidence.placement_evidence,
            MountedContentPlacementEvidence::ReceiptUnavailable {
                expected_generation: Some(_)
            }
        ));
        assert!(evidence.raw_media_diagnostic.object_key_hex.is_some());
        assert!(evidence.raw_media_diagnostic.reason.is_none());
    }

    #[test]
    fn scrub_chunk_refuses_stale_receipt_without_repair_dispatch() {
        let mut pool = temp_pool("stale-receipt");
        let payload = b"chunk plaintext evidence".to_vec();
        let record = test_file_record(17, 4, payload.len() as u64);
        let key = content_chunk_object_key_for_version(record.inode_id, record.data_version, 0);
        let encoded = encode_content_chunk(&record, 0, &payload, &ContentCompressionPolicy::off())
            .expect("encode stale-receipt chunk");
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
            FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
        );

        assert!(matches!(scrubbed.outcome, ScrubBlockOutcome::Unreadable(_)));
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
    }

    #[test]
    fn scrub_chunk_refuses_receiptless_pool_visible_raw_content() {
        let mut pool = temp_pool("receiptless-raw-content");
        let payload = b"receiptless raw chunk".to_vec();
        let record = test_file_record(18, 5, payload.len() as u64);
        let key = content_chunk_object_key_for_version(record.inode_id, record.data_version, 0);
        let encoded = encode_content_chunk(&record, 0, &payload, &ContentCompressionPolicy::off())
            .expect("encode receiptless chunk");
        let checksum = FastBlockChecksum::compute(&encoded);
        pool.raw_primary_store_mut()
            .put(key, &encoded)
            .expect("write receiptless raw chunk");
        let chunk_ref = ContentChunkRef {
            chunk_index: 0,
            data_version: record.data_version,
            len: payload.len() as u32,
            checksum,
            placement_receipt_generation: 1,
        };

        let scrubbed = scrub_content_chunk_with_pool(
            pool.raw_primary_store(),
            record.inode_id,
            &record,
            &chunk_ref,
            Some(&pool),
            FilesystemObjectKeyspace::new(tidefs_pool_runtime::ROOT_DATASET_ID),
        );

        assert!(matches!(scrubbed.outcome, ScrubBlockOutcome::Unreadable(_)));
        assert_eq!(
            scrubbed.evidence.placement_evidence,
            MountedContentPlacementEvidence::ReceiptMissing {
                expected_generation: Some(1),
            }
        );
        assert!(scrubbed
            .evidence
            .checksum_layer
            .as_ref()
            .expect("raw checksum diagnostic")
            .matches_expected());
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
    fn mounted_repair_classifies_later_receipt_target_without_reordering() {
        let expected = IntegrityDigest64(0x11);
        let target_outcomes = vec![
            MountedRepairTargetOutcome {
                device_index: 4,
                outcome: MountedRepairTargetChecksumOutcome::Clean { checksum: expected },
            },
            MountedRepairTargetOutcome {
                device_index: 9,
                outcome: MountedRepairTargetChecksumOutcome::Mismatch {
                    expected,
                    actual: IntegrityDigest64(0x22),
                },
            },
        ];
        let stable_outcomes = target_outcomes.clone();

        assert_eq!(
            classify_mounted_repair_targets(&target_outcomes),
            MountedRepairClassification::SingleReplicaCorruption {
                corrupt_target: 9,
                clean_sources: vec![4],
            }
        );
        assert_eq!(target_outcomes, stable_outcomes);

        let receipt_mismatch = vec![
            target_outcomes[0].clone(),
            MountedRepairTargetOutcome {
                device_index: 9,
                outcome: MountedRepairTargetChecksumOutcome::ReceiptMismatch { checksum: expected },
            },
        ];
        assert_eq!(
            classify_mounted_repair_targets(&receipt_mismatch),
            MountedRepairClassification::SingleReplicaCorruption {
                corrupt_target: 9,
                clean_sources: vec![4],
            }
        );
    }

    #[test]
    fn mounted_repair_dual_bad_targets_have_truthful_local_classification() {
        let expected = IntegrityDigest64(0x11);
        let same_bad = vec![
            MountedRepairTargetOutcome {
                device_index: 4,
                outcome: MountedRepairTargetChecksumOutcome::Mismatch {
                    expected,
                    actual: IntegrityDigest64(0x22),
                },
            },
            MountedRepairTargetOutcome {
                device_index: 9,
                outcome: MountedRepairTargetChecksumOutcome::Mismatch {
                    expected,
                    actual: IntegrityDigest64(0x22),
                },
            },
        ];
        assert_eq!(
            classify_mounted_repair_targets(&same_bad),
            MountedRepairClassification::ChecksumAuthorityDisagreement
        );

        let unreadable = vec![
            same_bad[0].clone(),
            MountedRepairTargetOutcome {
                device_index: 9,
                outcome: MountedRepairTargetChecksumOutcome::Unreadable,
            },
        ];
        assert_eq!(
            classify_mounted_repair_targets(&unreadable),
            MountedRepairClassification::ReceiptTargetDisagreement
        );
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
        // Mounted scrub verifies the committed Pool-readable root.  Publish
        // the accepted buffer before passing its inode version to the direct
        // committed-content diagnostic used by this unit test.
        fs.sync_all().expect("commit scrub test content");

        // Read back through scrub
        let inodes = fs.inode_records();
        let report = fs
            .scrub_mounted_content_records_for_test(inodes)
            .expect("scrub");
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
        let outcome = fs.scrub_content_chunk_for_test(&record, &chunk_ref);
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
