// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Integration bridge between local-filesystem scrub and scrub-core
//! automatic repair engine.
//!
//! The [`run_scrub_repair_pass`] function runs the detect→record pipeline:
//! it scrubs all inode content via the existing block-level checksum
//! verifier and records each corruption event in a BLAKE3-verified
//! [`ScrubRepairLedger`] with domain-separated validation hashing.
//!
//! In single-copy configurations (current local-filesystem), corrupt
//! blocks are recorded as failures (`repair_failure_count`). When
//! redundant storage becomes available, a [`BlockReconstructor`]
//! implementation can be wired in to attempt automatic reconstruction
//! and writeback, turning failures into successful repairs
//! (`repair_count`).

use tidefs_scrub::scrub_repair::ScrubRepairLedger;

use std::collections::BTreeMap;

use tidefs_local_object_store::SuspectEntry;
use tidefs_replication_model::PlacementReceiptRef;
use tidefs_scrub::repair_scheduling::{
    RebakeSchedulingBridge, RepairAdmissionInput, RepairBlockKind, RepairCandidateIdentity,
    RepairMountedChecksumEvidence, RepairMountedReceiptEvidenceStatus, RepairMountedScrubEvidence,
    RepairReplacementReceiptEvidence, ScrubToRepairBridge,
};
use tidefs_scrub::ChecksumLayer;

use crate::repair::RepairAuthorityMismatch;
use crate::scrub::{
    ScrubBlockEvidence, ScrubBlockId, ScrubBlockKind, ScrubBlockOutcome, ScrubReport,
    ScrubViolation,
};
use crate::types::{MountedContentChecksumLayer, MountedContentPlacementEvidence};

// ---------------------------------------------------------------------------
// run_scrub_repair_pass
// ---------------------------------------------------------------------------

/// Record scrub findings into a BLAKE3-verified validation ledger.
///
/// Each corrupt block found in the scrub report is recorded as a
/// [`ScrubRepairEvent`] with before/after hash information and the
/// block identity. In single-copy mode, all corruptions are recorded
/// as failures since no healthy replica is available for reconstruction.
///
/// When a [`BlockReconstructor`] is available (multi-replica or
/// erasure-coded redundancy), callers should use [`ScrubRepairEngine`]
/// directly to attempt automatic repair and writeback.
#[must_use]
pub fn run_scrub_repair_pass(report: &ScrubReport) -> ScrubRepairLedger {
    let mut ledger = ScrubRepairLedger::new();

    if report.is_clean() {
        return ledger;
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    for violation in &report.violations {
        let block_address = violation.block_id.inode_id;

        let expected_hash = match &violation.outcome {
            ScrubBlockOutcome::Corrupt { expected, .. } => {
                let mut hash = [0u8; 32];
                let bytes = expected.0.to_le_bytes();
                hash[..8].copy_from_slice(&bytes);
                hash
            }
            ScrubBlockOutcome::Unreadable(_) | ScrubBlockOutcome::NoChecksum => {
                // Record as failure with zero hashes — block cannot be
                // verified or repaired.
                ledger.record_failure(tidefs_scrub::scrub_repair::ScrubRepairEvent {
                    block_address,
                    expected_hash: [0u8; 32],
                    corrupted_hash: [0u8; 32],
                    rebuilt_hash: [0u8; 32],
                    shard_sources: vec![],
                    timestamp_secs: timestamp,
                    success: false,
                    integrity_outcome: None,
                });
                continue;
            }
            ScrubBlockOutcome::Clean => continue,
        };

        // In single-copy mode, all corruption is unrepairable —
        // no healthy replica exists. Record as failure.
        ledger.record_failure(tidefs_scrub::scrub_repair::ScrubRepairEvent {
            block_address,
            expected_hash,
            corrupted_hash: [0u8; 32], // actual corrupt hash not recoverable here
            rebuilt_hash: [0u8; 32],
            shard_sources: vec![],
            timestamp_secs: timestamp,
            success: false,
            integrity_outcome: None,
        });
    }

    ledger
}

// ---------------------------------------------------------------------------
// ScrubRepairSchedule — prioritized repair + rebake scheduling
// ---------------------------------------------------------------------------

/// Result of the scrub-to-repair scheduling pipeline.
///
/// Contains the [`ScrubToRepairBridge`] admission state, the
/// [`RebakeSchedulingBridge`] admission state, and the raw suspect entries
/// for audit/replay.
#[allow(dead_code)]
#[derive(Debug)]
pub struct ScrubRepairSchedule {
    pub bridge: ScrubToRepairBridge,
    pub rebake: RebakeSchedulingBridge,
    pub suspect_entries: Vec<SuspectEntry>,
}

// ---------------------------------------------------------------------------
// run_scrub_repair_scheduling
// ---------------------------------------------------------------------------

/// Wire scrub findings through the repair scheduling bridge and rebake
/// scheduling bridge.
///
/// Converts every [`ScrubViolation`] in the report into a [`SuspectEntry`],
/// classifies them through a [`ScrubToRepairBridge`], and attempts rebake
/// admission for payload-corruption findings that require EC parity
/// recomputation. Current local-filesystem scrub reports do not carry
/// placement receipts, so these findings are counted as blocked evidence
/// rather than queued repair work.
#[must_use]
#[allow(dead_code)]
pub fn run_scrub_repair_scheduling(report: &ScrubReport) -> ScrubRepairSchedule {
    let mut bridge = ScrubToRepairBridge::new();
    let mut rebake = RebakeSchedulingBridge::new();

    let repair_inputs = convert_violations_to_repair_inputs(report);
    let suspect_entries = repair_inputs.iter().map(|input| input.entry).collect();

    // Single-copy local filesystem: 0 replicas remaining.
    bridge.ingest_with_evidence(&repair_inputs, 0);

    // Generate rebake entries for payload corruption needing EC parity
    // recomputation. In single-copy mode this produces no entries.
    let _rebake_entries = rebake.generate_rebake_entries_with_evidence(&repair_inputs);

    ScrubRepairSchedule {
        bridge,
        rebake,
        suspect_entries,
    }
}

// ---------------------------------------------------------------------------
// convert_violations_to_repair_inputs
// ---------------------------------------------------------------------------

/// Convert [`ScrubReport`] violations into identity-bearing repair admission
/// inputs for ingestion by the scheduling bridges.
///
/// `SuspectEntry` mapping rules:
/// - `locator_id` ← `inode_id`
/// - `segment_id` ← `data_version`
/// - `offset` ← `chunk_index` for chunk corruption, 0 otherwise
/// - `record_type` = 1 for payload corruption, 3 for unreadable
fn convert_violations_to_repair_inputs(report: &ScrubReport) -> Vec<RepairAdmissionInput> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    report
        .violations
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let (record_type, expected_hash, actual_hash) = match &v.outcome {
                ScrubBlockOutcome::Corrupt { expected, actual } => {
                    let mut exp = [0u8; 32];
                    let mut act = [0u8; 32];
                    exp[..8].copy_from_slice(&expected.0.to_le_bytes());
                    act[..8].copy_from_slice(&actual.0.to_le_bytes());
                    (1u8, exp, act)
                }
                ScrubBlockOutcome::Unreadable(_) | ScrubBlockOutcome::NoChecksum => {
                    (3u8, [0u8; 32], [0u8; 32])
                }
                ScrubBlockOutcome::Clean => (0u8, [0u8; 32], [0u8; 32]),
            };

            let offset = match &v.block_id.kind {
                crate::scrub::ScrubBlockKind::ContentChunk { chunk_index } => *chunk_index,
                _ => 0,
            };

            let entry = SuspectEntry {
                entry_id: i as u64,
                locator_id: v.block_id.inode_id,
                segment_id: v.block_id.data_version,
                offset,
                record_type,
                expected_hash,
                actual_hash,
                repair_attempts: 0,
                last_repair_attempt: 0,
                resolved: false,
                commit_group: 0,
                timestamp_secs: timestamp,
            };
            let identity = repair_identity_from_scrub_block_id(&v.block_id);
            let scrub_evidence = report.block_evidence.get(&v.block_id);
            let mut input = if let Some(receipt) = scrub_evidence.and_then(|evidence| {
                placement_receipt_ref_from_mounted_scrub_evidence(&entry, evidence)
            }) {
                RepairAdmissionInput::with_receipt_and_identity(entry, receipt, identity)
            } else {
                RepairAdmissionInput::missing_receipt_with_identity(entry, identity)
            };
            if let Some(evidence) =
                scrub_evidence.map(repair_mounted_scrub_evidence_from_scrub_evidence)
            {
                input = input.with_mounted_scrub_evidence(evidence);
            }
            input
        })
        .collect()
}

fn repair_identity_from_scrub_block_id(block_id: &ScrubBlockId) -> RepairCandidateIdentity {
    RepairCandidateIdentity::new(
        block_id.inode_id,
        block_id.data_version,
        repair_kind_from_scrub_kind(block_id.kind),
    )
}

fn repair_kind_from_scrub_kind(kind: ScrubBlockKind) -> RepairBlockKind {
    match kind {
        ScrubBlockKind::InlineContent => RepairBlockKind::InlineContent,
        ScrubBlockKind::ContentManifest => RepairBlockKind::ContentManifest,
        ScrubBlockKind::ContentChunk { chunk_index } => {
            RepairBlockKind::ContentChunk { chunk_index }
        }
    }
}

fn checksum_layer_for_repair_kind(kind: RepairBlockKind) -> ChecksumLayer {
    match kind {
        RepairBlockKind::InlineContent | RepairBlockKind::ContentManifest => {
            ChecksumLayer::InlineContentBody
        }
        RepairBlockKind::ContentChunk { .. } => ChecksumLayer::EncodedContentChunk,
    }
}

fn placement_receipt_ref_from_mounted_scrub_evidence(
    entry: &SuspectEntry,
    evidence: &ScrubBlockEvidence,
) -> Option<PlacementReceiptRef> {
    let subject = repair_identity_from_scrub_block_id(&evidence.plaintext_identity.block_id);
    if !subject.matches_suspect_entry(entry) {
        return None;
    }

    let MountedContentPlacementEvidence::ReceiptVerified {
        placement_receipt_ref,
        ..
    } = &evidence.placement_evidence
    else {
        return None;
    };

    if placement_receipt_ref.object_id != entry.locator_id
        || placement_receipt_ref.payload_len != evidence.plaintext_identity.expected_plaintext_len
        || placement_receipt_ref.payload_digest != entry.expected_hash
        || placement_receipt_ref.target_count <= 1
        || !placement_receipt_ref.is_committed_authority()
    {
        return None;
    }

    Some(*placement_receipt_ref)
}

fn repair_mounted_scrub_evidence_from_scrub_evidence(
    evidence: &ScrubBlockEvidence,
) -> RepairMountedScrubEvidence {
    let checksum = evidence
        .checksum_layer
        .as_ref()
        .map(|checksum| RepairMountedChecksumEvidence {
            layer: repair_checksum_layer_from_mounted(checksum.layer),
            expected: checksum.expected.map(repair_digest_from_integrity),
            actual: repair_digest_from_integrity(checksum.actual),
            encoded_len: checksum.encoded_len,
        })
        .unwrap_or_else(|| RepairMountedChecksumEvidence {
            layer: repair_checksum_layer_from_scrub_kind(evidence.plaintext_identity.block_id.kind),
            expected: None,
            actual: [0u8; 32],
            encoded_len: 0,
        });
    RepairMountedScrubEvidence {
        subject: repair_identity_from_scrub_block_id(&evidence.plaintext_identity.block_id),
        expected_plaintext_len: evidence.plaintext_identity.expected_plaintext_len,
        observed_plaintext_len: evidence.plaintext_identity.observed_plaintext_len,
        checksum,
        receipt_status: repair_receipt_status_from_mounted(&evidence.placement_evidence),
    }
}

fn repair_checksum_layer_from_mounted(layer: MountedContentChecksumLayer) -> ChecksumLayer {
    match layer {
        MountedContentChecksumLayer::InlineContentBody => ChecksumLayer::InlineContentBody,
        MountedContentChecksumLayer::EncodedContentChunk => ChecksumLayer::EncodedContentChunk,
        MountedContentChecksumLayer::SparseHole => ChecksumLayer::SparseHole,
    }
}

fn repair_checksum_layer_from_scrub_kind(kind: ScrubBlockKind) -> ChecksumLayer {
    match kind {
        ScrubBlockKind::InlineContent | ScrubBlockKind::ContentManifest => {
            ChecksumLayer::InlineContentBody
        }
        ScrubBlockKind::ContentChunk { .. } => ChecksumLayer::EncodedContentChunk,
    }
}

fn repair_receipt_status_from_mounted(
    evidence: &MountedContentPlacementEvidence,
) -> RepairMountedReceiptEvidenceStatus {
    match evidence {
        MountedContentPlacementEvidence::SparseHole => {
            RepairMountedReceiptEvidenceStatus::SparseHole
        }
        MountedContentPlacementEvidence::ReceiptVerified { generation, .. } => {
            RepairMountedReceiptEvidenceStatus::ReceiptVerified {
                generation: *generation,
            }
        }
        MountedContentPlacementEvidence::ReceiptObservedButUnbound { generation } => {
            RepairMountedReceiptEvidenceStatus::ReceiptObservedButUnbound {
                generation: *generation,
            }
        }
        MountedContentPlacementEvidence::ReceiptMissing {
            expected_generation,
        } => RepairMountedReceiptEvidenceStatus::ReceiptMissing {
            expected_generation: *expected_generation,
        },
        MountedContentPlacementEvidence::ReceiptStale {
            expected_generation,
            observed_generation,
        } => RepairMountedReceiptEvidenceStatus::ReceiptStale {
            expected_generation: *expected_generation,
            observed_generation: *observed_generation,
        },
        MountedContentPlacementEvidence::ReceiptUnavailable {
            expected_generation,
        } => RepairMountedReceiptEvidenceStatus::ReceiptUnavailable {
            expected_generation: *expected_generation,
        },
    }
}

fn repair_digest_from_integrity(digest: tidefs_local_object_store::IntegrityDigest64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&digest.0.to_le_bytes());
    bytes
}

// ---------------------------------------------------------------------------
// dispatch_repair_from_bridge
// ---------------------------------------------------------------------------

/// Dispatch prioritized repair jobs from the [`ScrubToRepairBridge`] through
/// the filesystem repair pipeline.
///
/// Iterates jobs in priority order (Immediate → Urgent → Normal →
/// Background), resolves each into a repair strategy via
/// [`crate::repair::resolve_violation`], and applies the repair through
/// [`crate::repair::apply_one_repair`].
///
/// Repaired jobs are marked resolved in the bridge; failed jobs are
/// escalated and may be marked exhausted after max attempts.
#[allow(dead_code)]
pub fn dispatch_repair_from_bridge(
    bridge: &mut ScrubToRepairBridge,
    state: &mut crate::FileSystemState,
    store: &mut tidefs_local_object_store::LocalObjectStore,
    content_layout_cache: &mut BTreeMap<
        tidefs_types_vfs_core::InodeId,
        crate::records::ContentLayout,
    >,
) -> crate::repair::RepairLog {
    let mut applied_log = crate::repair::RepairLog::new();

    // Snapshot locator IDs to avoid borrow conflicts during mutation.
    let locator_ids: Vec<u64> = bridge
        .prioritized_jobs()
        .iter()
        .map(|j| j.entry.locator_id)
        .collect();

    for locator_id in locator_ids {
        // Look up current job state for this locator.
        let all_jobs: Vec<_> = bridge.prioritized_jobs().into_iter().cloned().collect();
        let job = match all_jobs.iter().find(|j| j.entry.locator_id == locator_id) {
            Some(j) => j.clone(),
            None => continue, // already removed (exhausted)
        };

        let violation = repair_job_to_violation(&job);
        let ctx = crate::repair::ResolverContext {
            redundancy_available: job.replicas_remaining > 0,
        };
        let strategy = crate::repair::resolve_violation(&violation, ctx);

        if let Err(reason) = verify_mounted_scrub_dispatch_evidence(&job) {
            let outcome = crate::repair::RepairOutcome::AuthorityMismatch { reason };
            applied_log.record(crate::repair::RepairEntry {
                block_id: violation.block_id,
                strategy,
                outcome,
            });
            bridge.mark_authority_mismatch(locator_id);
            continue;
        }

        let entry = crate::repair::RepairEntry {
            block_id: violation.block_id.clone(),
            strategy,
            outcome: crate::repair::RepairOutcome::Skipped,
        };

        if let Err(reason) =
            verify_current_repair_authority(&entry.block_id, state, store, content_layout_cache)
        {
            let outcome = crate::repair::RepairOutcome::AuthorityMismatch { reason };
            applied_log.record(crate::repair::RepairEntry {
                block_id: entry.block_id,
                strategy: entry.strategy,
                outcome,
            });
            bridge.mark_authority_mismatch(locator_id);
            continue;
        }

        let replacement_receipt = match entry.strategy {
            crate::scrub::RepairStrategy::Reconstruct => replacement_receipt_evidence_for_job(&job),
            crate::scrub::RepairStrategy::Truncate | crate::scrub::RepairStrategy::MarkCorrupt => {
                None
            }
        };
        let outcome = crate::repair::apply_one_repair_with_replacement_evidence(
            &entry,
            state,
            store,
            content_layout_cache,
            replacement_receipt,
        );

        applied_log.record(crate::repair::RepairEntry {
            block_id: entry.block_id,
            strategy: entry.strategy,
            outcome: outcome.clone(),
        });

        // In single-copy mode (replicas_remaining == 0), MarkedCorrupt is
        // data-loss containment, not a repair. Only Truncated and
        // Reconstructed are true repairs. In multi-replica mode the
        // resolver should prefer Reconstruct before MarkCorrupt.
        match &outcome {
            crate::repair::RepairOutcome::Reconstructed { .. }
            | crate::repair::RepairOutcome::Truncated { .. } => {
                bridge.mark_repaired(locator_id);
            }
            crate::repair::RepairOutcome::AuthorityMismatch { .. } => {
                bridge.mark_authority_mismatch(locator_id);
            }
            crate::repair::RepairOutcome::MarkedCorrupt
            | crate::repair::RepairOutcome::WritebackMissingReplacementReceipt { .. }
            | crate::repair::RepairOutcome::StorageIoFailure { .. }
            | crate::repair::RepairOutcome::Unrepairable { .. }
            | crate::repair::RepairOutcome::Skipped => {
                bridge.mark_failed(locator_id);
            }
        }
    }

    applied_log
}

fn verify_mounted_scrub_dispatch_evidence(
    job: &tidefs_scrub::repair_scheduling::RepairJob,
) -> Result<(), RepairAuthorityMismatch> {
    let evidence = job.evidence.mounted_scrub_evidence;
    if evidence.checksum.expected.is_none() {
        return Err(RepairAuthorityMismatch::MountedScrubChecksumMissing);
    }
    if evidence.checksum.layer != checksum_layer_for_repair_kind(job.candidate_identity.kind) {
        return Err(RepairAuthorityMismatch::MountedScrubEvidenceStale);
    }
    if evidence.subject != job.candidate_identity
        || !evidence.subject.matches_suspect_entry(&job.entry)
        || evidence.checksum.expected != Some(job.entry.expected_hash)
        || evidence.checksum.actual != job.entry.actual_hash
    {
        return Err(RepairAuthorityMismatch::MountedScrubEvidenceStale);
    }
    if let RepairMountedReceiptEvidenceStatus::ReceiptVerified { generation } =
        evidence.receipt_status
    {
        if generation != job.evidence.placement_receipt_ref.receipt_generation {
            return Err(RepairAuthorityMismatch::MountedScrubEvidenceStale);
        }
    }
    if !evidence.receipt_status.allows_repair_dispatch() {
        return Err(RepairAuthorityMismatch::MountedScrubReceiptNotVerified);
    }

    Ok(())
}

fn replacement_receipt_evidence_for_job(
    job: &tidefs_scrub::repair_scheduling::RepairJob,
) -> Option<RepairReplacementReceiptEvidence> {
    let source = job.evidence.placement_receipt_ref;
    let replacement = tidefs_replication_model::PlacementReceiptRef::new(
        source.object_id,
        source.object_key,
        source.receipt_epoch,
        source.receipt_generation.saturating_add(1),
        source.redundancy_policy,
        source.payload_len,
        source.payload_digest,
        source.target_count,
    );
    let replacement_receipt_id =
        replacement_receipt_id_for_job(job, replacement.receipt_generation);

    RepairReplacementReceiptEvidence::new(
        job.candidate_identity,
        crate::ack_receipt::LOCAL_ACK_POLICY_REVISION.0,
        source,
        job.evidence.mounted_scrub_evidence,
        replacement,
        replacement_receipt_id,
    )
    .ok()
}

fn replacement_receipt_id_for_job(
    job: &tidefs_scrub::repair_scheduling::RepairJob,
    replacement_generation: u64,
) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tidefs-local-repair-replacement-receipt-v1");
    hasher.update(&job.candidate_identity.inode_id.to_le_bytes());
    hasher.update(&job.candidate_identity.data_version.to_le_bytes());
    match job.candidate_identity.kind {
        RepairBlockKind::InlineContent => {
            hasher.update(&[0]);
        }
        RepairBlockKind::ContentManifest => {
            hasher.update(&[1]);
        }
        RepairBlockKind::ContentChunk { chunk_index } => {
            hasher.update(&[2]);
            hasher.update(&chunk_index.to_le_bytes());
        }
    };
    hasher.update(&job.evidence.placement_receipt_ref.object_key);
    hasher.update(
        &job.evidence
            .placement_receipt_ref
            .receipt_generation
            .to_le_bytes(),
    );
    hasher.update(&replacement_generation.to_le_bytes());

    let mut id = [0u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    id
}

/// Reconstruct a [`ScrubViolation`] from a [`RepairJob`] so the existing
/// repair resolution pipeline can consume it.
fn repair_job_to_violation(job: &tidefs_scrub::repair_scheduling::RepairJob) -> ScrubViolation {
    let entry = &job.entry;
    let kind = scrub_kind_from_repair_kind(job.candidate_identity.kind);

    let block_id = crate::scrub::ScrubBlockId {
        inode_id: job.candidate_identity.inode_id,
        data_version: job.candidate_identity.data_version,
        kind,
    };

    let outcome = if entry.record_type == 1 {
        ScrubBlockOutcome::Corrupt {
            expected: tidefs_local_object_store::IntegrityDigest64(u64::from_le_bytes([
                entry.expected_hash[0],
                entry.expected_hash[1],
                entry.expected_hash[2],
                entry.expected_hash[3],
                entry.expected_hash[4],
                entry.expected_hash[5],
                entry.expected_hash[6],
                entry.expected_hash[7],
            ])),
            actual: tidefs_local_object_store::IntegrityDigest64(u64::from_le_bytes([
                entry.actual_hash[0],
                entry.actual_hash[1],
                entry.actual_hash[2],
                entry.actual_hash[3],
                entry.actual_hash[4],
                entry.actual_hash[5],
                entry.actual_hash[6],
                entry.actual_hash[7],
            ])),
        }
    } else {
        ScrubBlockOutcome::Unreadable("dispatched from suspect log".into())
    };

    ScrubViolation {
        block_id,
        key_hex: format!("{:016x}", entry.locator_id),
        outcome,
    }
}

fn scrub_kind_from_repair_kind(kind: RepairBlockKind) -> ScrubBlockKind {
    match kind {
        RepairBlockKind::InlineContent => ScrubBlockKind::InlineContent,
        RepairBlockKind::ContentManifest => ScrubBlockKind::ContentManifest,
        RepairBlockKind::ContentChunk { chunk_index } => {
            ScrubBlockKind::ContentChunk { chunk_index }
        }
    }
}

fn verify_current_repair_authority(
    block_id: &ScrubBlockId,
    state: &crate::FileSystemState,
    store: &tidefs_local_object_store::LocalObjectStore,
    content_layout_cache: &mut BTreeMap<
        tidefs_types_vfs_core::InodeId,
        crate::records::ContentLayout,
    >,
) -> Result<(), RepairAuthorityMismatch> {
    let inode_id = tidefs_types_vfs_core::InodeId::new(block_id.inode_id);
    let record = state
        .inodes
        .get(&inode_id)
        .ok_or(RepairAuthorityMismatch::MissingInode)?;
    if !record.is_file_like() {
        return Err(RepairAuthorityMismatch::BlockKindMismatch);
    }

    match block_id.kind {
        ScrubBlockKind::InlineContent => {
            if record.data_version != block_id.data_version {
                return Err(RepairAuthorityMismatch::DataVersionStale {
                    candidate: block_id.data_version,
                    current: record.data_version,
                });
            }
            Ok(())
        }
        ScrubBlockKind::ContentManifest => {
            if record.data_version != block_id.data_version {
                return Err(RepairAuthorityMismatch::DataVersionStale {
                    candidate: block_id.data_version,
                    current: record.data_version,
                });
            }
            match current_content_layout(inode_id, record, store, content_layout_cache)? {
                crate::records::ContentLayout::Chunked(_) => Ok(()),
                crate::records::ContentLayout::Inline(_) => {
                    Err(RepairAuthorityMismatch::BlockKindMismatch)
                }
            }
        }
        ScrubBlockKind::ContentChunk { chunk_index } => {
            match current_content_layout(inode_id, record, store, content_layout_cache)? {
                crate::records::ContentLayout::Chunked(manifest) => {
                    let Some(chunk_ref) = manifest
                        .chunks
                        .iter()
                        .find(|chunk| chunk.chunk_index == chunk_index)
                    else {
                        return Err(RepairAuthorityMismatch::BlockKindMismatch);
                    };
                    if chunk_ref.is_hole() {
                        return Err(RepairAuthorityMismatch::BlockKindMismatch);
                    }
                    if chunk_ref.data_version != block_id.data_version {
                        return Err(RepairAuthorityMismatch::DataVersionStale {
                            candidate: block_id.data_version,
                            current: chunk_ref.data_version,
                        });
                    }
                    Ok(())
                }
                crate::records::ContentLayout::Inline(_) => {
                    Err(RepairAuthorityMismatch::BlockKindMismatch)
                }
            }
        }
    }
}

fn current_content_layout(
    inode_id: tidefs_types_vfs_core::InodeId,
    record: &crate::types::InodeRecord,
    store: &tidefs_local_object_store::LocalObjectStore,
    content_layout_cache: &mut BTreeMap<
        tidefs_types_vfs_core::InodeId,
        crate::records::ContentLayout,
    >,
) -> Result<crate::records::ContentLayout, RepairAuthorityMismatch> {
    if let Some(layout) = content_layout_cache.get(&inode_id) {
        return Ok(layout.clone());
    }

    let layout = crate::content::read_content_layout_from_store(store, inode_id, record)
        .map_err(|_| RepairAuthorityMismatch::CurrentAuthorityUnavailable)?;
    content_layout_cache.insert(inode_id, layout.clone());
    Ok(layout)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scrub::{
        ScrubBlockId, ScrubBlockKind, ScrubBlockOutcome, ScrubPlaintextIdentity,
        ScrubRawMediaDiagnostic, ScrubReport, ScrubViolation,
    };
    use tidefs_local_object_store::IntegrityDigest64;
    use tidefs_scrub::repair_scheduling::{RepairBlockKind, RepairCandidateIdentity};
    use tidefs_scrub::{
        ChecksumLayer, ComparisonClassification, CrossReplicaComparisonRecord, ScrubSubject,
        ScrubSubjectKind,
    };
    use tidefs_types_vfs_core::{Generation, InodeId, NodeKind};

    fn make_file_inode(inode_id: u64, data_version: u64, size: u64) -> crate::types::InodeRecord {
        crate::types::InodeRecord {
            rdev: 0,
            inode_id: InodeId::new(inode_id),
            generation: Generation(data_version),
            facets: NodeKind::File.to_facets(),
            mode: 0o644,
            uid: 0,
            gid: 0,
            nlink: 1,
            size,
            data_version,
            metadata_version: data_version,
            posix_time: crate::types::PosixTimeRecord::now(),
            xattrs: Default::default(),
            dir_storage_kind: 0,
            xattr_storage_kind: 0,
            dir_rev: 0,
            subtree_rev: 0,
        }
    }

    fn insert_inode(state: &mut crate::FileSystemState, inode: crate::types::InodeRecord) {
        let inode_id = inode.inode_id;
        std::sync::Arc::make_mut(&mut state.inodes).insert(inode.inode_id, inode);
        state.observe_explicit_inode_id(inode_id);
    }

    fn temp_store() -> tidefs_local_object_store::LocalObjectStore {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT_ID: AtomicU32 = AtomicU32::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "tidefs-scrub-repair-integration-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create test store dir");
        tidefs_local_object_store::LocalObjectStore::open(&dir).expect("open test store")
    }

    fn make_suspect_entry(
        inode_id: u64,
        data_version: u64,
        offset: u64,
    ) -> tidefs_local_object_store::SuspectEntry {
        tidefs_local_object_store::SuspectEntry {
            entry_id: inode_id,
            locator_id: inode_id,
            segment_id: data_version,
            offset,
            record_type: 1,
            expected_hash: [0xAA; 32],
            actual_hash: [0xBB; 32],
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: data_version.max(1),
            timestamp_secs: 1,
        }
    }

    fn receipt_for_entry(entry: &tidefs_local_object_store::SuspectEntry) -> PlacementReceiptRef {
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&entry.locator_id.to_le_bytes());
        PlacementReceiptRef::replicated(
            entry.locator_id,
            object_key,
            Default::default(),
            entry.commit_group.max(1),
            2,
            4096,
            entry.expected_hash,
        )
    }

    fn mounted_scrub_evidence_for_entry(
        entry: &tidefs_local_object_store::SuspectEntry,
        kind: RepairBlockKind,
        receipt_generation: u64,
    ) -> RepairMountedScrubEvidence {
        RepairMountedScrubEvidence {
            subject: RepairCandidateIdentity::new(entry.locator_id, entry.segment_id, kind),
            expected_plaintext_len: 4096,
            observed_plaintext_len: Some(4096),
            checksum: RepairMountedChecksumEvidence {
                layer: checksum_layer_for_repair_kind(kind),
                expected: Some(entry.expected_hash),
                actual: entry.actual_hash,
                encoded_len: 4096,
            },
            receipt_status: RepairMountedReceiptEvidenceStatus::ReceiptVerified {
                generation: receipt_generation,
            },
        }
    }

    fn input_for_identity(
        inode_id: u64,
        data_version: u64,
        kind: RepairBlockKind,
    ) -> RepairAdmissionInput {
        let offset = match kind {
            RepairBlockKind::ContentChunk { chunk_index } => chunk_index,
            RepairBlockKind::InlineContent | RepairBlockKind::ContentManifest => 0,
        };
        let entry = make_suspect_entry(inode_id, data_version, offset);
        let receipt = receipt_for_entry(&entry);
        let comparison = comparison_record_for_entry(&entry, kind);
        let identity = RepairCandidateIdentity::new(inode_id, data_version, kind);
        let mounted = mounted_scrub_evidence_for_entry(&entry, kind, receipt.receipt_generation);
        RepairAdmissionInput::with_receipt_and_identity(entry, receipt, identity)
            .with_mounted_scrub_evidence(mounted)
            .with_cross_replica_comparison(&comparison)
    }

    fn comparison_record_for_entry(
        entry: &tidefs_local_object_store::SuspectEntry,
        kind: RepairBlockKind,
    ) -> CrossReplicaComparisonRecord {
        let receipt = receipt_for_entry(entry);
        CrossReplicaComparisonRecord {
            subject: ScrubSubject {
                inode_id: entry.locator_id,
                data_version: entry.segment_id,
                kind: subject_kind_for_repair_kind(kind),
            },
            object_key: receipt.object_key,
            checksum_layer: checksum_layer_for_repair_kind(kind),
            redundancy_policy_id: 1,
            target_count: receipt.target_count,
            placement_receipt_epoch: receipt.receipt_epoch.0,
            placement_receipt_generation: receipt.receipt_generation,
            membership_epoch: 1,
            replica_outcomes: Vec::new(),
            classification: ComparisonClassification::SingleReplicaCorruption {
                corrupt_replica: 1,
                clean_sources: vec![2],
            },
            clean_source_set: vec![2],
            corrupt_target_set: vec![1],
        }
    }

    fn subject_kind_for_repair_kind(kind: RepairBlockKind) -> ScrubSubjectKind {
        match kind {
            RepairBlockKind::InlineContent => ScrubSubjectKind::InlineContent,
            RepairBlockKind::ContentManifest => ScrubSubjectKind::ContentManifest,
            RepairBlockKind::ContentChunk { chunk_index } => {
                ScrubSubjectKind::ContentChunk { chunk_index }
            }
        }
    }

    fn checksum_layer_for_repair_kind(kind: RepairBlockKind) -> ChecksumLayer {
        match kind {
            RepairBlockKind::InlineContent | RepairBlockKind::ContentManifest => {
                ChecksumLayer::InlineContentBody
            }
            RepairBlockKind::ContentChunk { .. } => ChecksumLayer::EncodedContentChunk,
        }
    }

    fn encoded_reconstructable_object() -> (Vec<u8>, Vec<u8>) {
        let config = tidefs_erasure_coding::StripeConfig {
            data_shards: 2,
            parity_shards: 1,
            shard_len: 8,
        };
        let payload: Vec<u8> = (0..16).collect();
        let encoded = tidefs_erasure_coding::encode(&config, &payload).expect("encode");
        let mut raw = Vec::new();
        raw.extend_from_slice(&(config.stripe_width() as u16).to_le_bytes());
        raw.extend_from_slice(&(config.data_shards as u16).to_le_bytes());
        raw.push(config.parity_shards as u8);
        raw.extend_from_slice(&(config.shard_len as u32).to_le_bytes());
        for shard in &encoded.shards {
            raw.extend_from_slice(&shard.bytes);
        }
        (raw, payload)
    }

    #[test]
    fn clean_report_returns_empty_ledger() {
        let report = ScrubReport::empty();
        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 0);
        assert_eq!(ledger.event_count(), 0);
    }

    #[test]
    fn corrupt_blocks_recorded_as_failures() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 2;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 10,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "000000000000000000000000000000000000000000000000000000000000000a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xCAFE),
                actual: IntegrityDigest64(0xBABE),
            },
        });
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 20,
                data_version: 2,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 0 },
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000014".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xDEAD),
                actual: IntegrityDigest64(0xBEEF),
            },
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_count, 0);
        assert_eq!(ledger.repair_failure_count, 2);
        assert_eq!(ledger.event_count(), 2);
    }

    #[test]
    fn validation_digest_nonzero_for_nonempty() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 1,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000001".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(1),
                actual: IntegrityDigest64(2),
            },
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_ne!(ledger.validation_digest(), [0u8; 32]);
    }

    #[test]
    fn unreadable_blocks_recorded_as_failures() {
        let mut report = ScrubReport::empty();
        report.blocks_unreadable = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 99,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0000000000000000000000000000000000000000000000000000000000000063".into(),
            outcome: ScrubBlockOutcome::Unreadable("disk error".into()),
        });

        let ledger = run_scrub_repair_pass(&report);
        assert_eq!(ledger.repair_failure_count, 1);
        assert_eq!(ledger.repair_count, 0);
    }

    // ── run_scrub_repair_scheduling tests ──────────────────────────

    #[test]
    fn scheduling_bridge_blocks_receiptless_corrupt_report() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 1;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 42,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "000000000000000000000000000000000000000000000000000000000000002a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xABCD),
                actual: IntegrityDigest64(0x1234),
            },
        });

        let schedule = run_scrub_repair_scheduling(&report);

        // Receiptless scrub findings are blocked rather than scheduled.
        assert!(!schedule.bridge.has_work());
        assert_eq!(schedule.bridge.pending_count(), 0);
        assert_eq!(
            schedule
                .bridge
                .stats()
                .entries_blocked_missing_mounted_scrub_evidence,
            1
        );

        // Suspect entries are populated.
        assert_eq!(schedule.suspect_entries.len(), 1);
        let suspect = &schedule.suspect_entries[0];
        assert_eq!(suspect.locator_id, 42);
        assert_eq!(suspect.record_type, 1u8); // payload corruption

        // Single-copy mode: no rebake entries.
        assert_eq!(schedule.rebake.entries_generated(), 0);
        assert_eq!(
            schedule
                .rebake
                .entries_blocked_missing_mounted_scrub_evidence(),
            1
        );
    }

    #[test]
    fn scheduling_bridge_empty_for_clean_report() {
        let report = ScrubReport::empty();
        let schedule = run_scrub_repair_scheduling(&report);

        assert!(!schedule.bridge.has_work());
        assert_eq!(schedule.bridge.pending_count(), 0);
        assert!(schedule.suspect_entries.is_empty());
    }

    #[test]
    fn scheduling_bridge_blocks_receiptless_single_copy_findings() {
        let mut report = ScrubReport::empty();
        report.blocks_corrupt = 2;
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 10,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "0a".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(1),
                actual: IntegrityDigest64(2),
            },
        });
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 20,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "14".into(),
            outcome: ScrubBlockOutcome::Unreadable("io error".into()),
        });

        let schedule = run_scrub_repair_scheduling(&report);

        assert_eq!(schedule.bridge.prioritized_jobs().len(), 0);
        assert_eq!(
            schedule
                .bridge
                .stats()
                .entries_blocked_missing_mounted_scrub_evidence,
            2
        );
        assert_eq!(
            schedule
                .rebake
                .entries_blocked_missing_mounted_scrub_evidence(),
            2
        );
    }

    #[test]
    fn dispatch_fresh_generation_writeback_publishes_replacement_receipt() {
        let inode_id = 510;
        let data_version = 1;
        let mut state = crate::recovery::initial_state();
        insert_inode(&mut state, make_file_inode(inode_id, data_version, 16));
        let mut store = temp_store();
        let key = crate::object_keys::content_object_key_for_version(
            InodeId::new(inode_id),
            data_version,
        );
        let (raw, payload) = encoded_reconstructable_object();
        store.put(key, &raw).expect("store corrupt EC object");

        let mut bridge = ScrubToRepairBridge::new();
        let input = input_for_identity(inode_id, data_version, RepairBlockKind::InlineContent);
        let source_receipt = input.placement_receipt_ref.expect("source receipt");
        let admissions = bridge.ingest_with_evidence(&[input], 1);
        assert_eq!(admissions.len(), 1);
        assert_eq!(bridge.pending_count(), 1);

        let applied =
            dispatch_repair_from_bridge(&mut bridge, &mut state, &mut store, &mut BTreeMap::new());

        assert_eq!(applied.len(), 1);
        let crate::repair::RepairOutcome::Reconstructed {
            bytes_written,
            ref replacement_receipt,
        } = applied.entries[0].outcome
        else {
            panic!(
                "expected reconstructed receipt outcome, got {:?}",
                applied.entries[0].outcome
            );
        };
        assert_eq!(bytes_written, 16);
        assert_eq!(
            replacement_receipt.subject,
            RepairCandidateIdentity::new(inode_id, data_version, RepairBlockKind::InlineContent)
        );
        assert_eq!(
            replacement_receipt.source_placement_receipt_ref,
            source_receipt
        );
        assert_eq!(
            replacement_receipt.mounted_scrub_evidence.receipt_status,
            RepairMountedReceiptEvidenceStatus::ReceiptVerified {
                generation: source_receipt.receipt_generation,
            }
        );
        assert_eq!(
            replacement_receipt.replacement_receipt_generation(),
            source_receipt.receipt_generation + 1
        );
        assert_ne!(replacement_receipt.replacement_receipt_id, [0; 16]);
        assert_eq!(
            applied.entries[0]
                .outcome
                .replacement_receipt_evidence()
                .expect("replacement evidence")
                .downstream_evidence(),
            replacement_receipt.downstream_evidence()
        );
        assert_eq!(store.get(key).expect("read key").expect("stored"), payload);
        assert_eq!(bridge.repaired_count(), 1);
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.stats().entries_blocked_authority_mismatch, 0);
    }

    #[test]
    fn dispatch_stale_generation_refuses_writeback_to_newer_object() {
        let inode_id = 511;
        let candidate_version = 1;
        let current_version = 2;
        let mut state = crate::recovery::initial_state();
        insert_inode(&mut state, make_file_inode(inode_id, current_version, 16));
        let mut store = temp_store();
        let old_key = crate::object_keys::content_object_key_for_version(
            InodeId::new(inode_id),
            candidate_version,
        );
        let current_key = crate::object_keys::content_object_key_for_version(
            InodeId::new(inode_id),
            current_version,
        );
        let (raw, _) = encoded_reconstructable_object();
        let newer_bytes = b"newer-content-authority".to_vec();
        store.put(old_key, &raw).expect("store stale EC object");
        store
            .put(current_key, &newer_bytes)
            .expect("store current content object");

        let mut bridge = ScrubToRepairBridge::new();
        let input = input_for_identity(inode_id, candidate_version, RepairBlockKind::InlineContent);
        bridge.ingest_with_evidence(&[input], 1);

        let applied =
            dispatch_repair_from_bridge(&mut bridge, &mut state, &mut store, &mut BTreeMap::new());

        assert_eq!(applied.len(), 1);
        assert_eq!(
            applied.entries[0].outcome,
            crate::repair::RepairOutcome::AuthorityMismatch {
                reason: RepairAuthorityMismatch::DataVersionStale {
                    candidate: candidate_version,
                    current: current_version,
                },
            }
        );
        assert_eq!(
            store
                .get(current_key)
                .expect("read current key")
                .expect("current object"),
            newer_bytes
        );
        assert_eq!(bridge.pending_count(), 0);
        assert_eq!(bridge.repaired_count(), 0);
        assert_eq!(bridge.stats().entries_blocked_authority_mismatch, 1);
    }

    // ── convert_violations_to_repair_inputs tests ─────────────────

    fn repair_input_entries(report: &ScrubReport) -> Vec<SuspectEntry> {
        convert_violations_to_repair_inputs(report)
            .into_iter()
            .map(|input| input.entry)
            .collect()
    }

    fn digest64_bytes(digest: IntegrityDigest64) -> [u8; 32] {
        let mut hash = [0u8; 32];
        hash[..8].copy_from_slice(&digest.0.to_le_bytes());
        hash
    }

    fn placement_receipt_ref_for_evidence(
        block_id: &ScrubBlockId,
        expected: IntegrityDigest64,
        generation: u64,
        copies: u8,
    ) -> PlacementReceiptRef {
        let mut object_key = [0u8; 32];
        object_key[..8].copy_from_slice(&block_id.inode_id.to_le_bytes());
        PlacementReceiptRef::replicated(
            block_id.inode_id,
            object_key,
            Default::default(),
            generation,
            copies,
            4096,
            digest64_bytes(expected),
        )
    }

    fn mounted_scrub_block_evidence(
        block_id: ScrubBlockId,
        expected: IntegrityDigest64,
        actual: IntegrityDigest64,
        receipt_generation: u64,
    ) -> ScrubBlockEvidence {
        let placement_receipt_ref =
            placement_receipt_ref_for_evidence(&block_id, expected, receipt_generation, 2);
        mounted_scrub_block_evidence_with_placement(
            block_id,
            expected,
            actual,
            MountedContentPlacementEvidence::ReceiptVerified {
                generation: receipt_generation,
                placement_receipt_ref,
            },
        )
    }

    fn mounted_scrub_block_evidence_with_placement(
        block_id: ScrubBlockId,
        expected: IntegrityDigest64,
        actual: IntegrityDigest64,
        placement_evidence: MountedContentPlacementEvidence,
    ) -> ScrubBlockEvidence {
        let checksum_layer = match block_id.kind {
            ScrubBlockKind::InlineContent | ScrubBlockKind::ContentManifest => {
                MountedContentChecksumLayer::InlineContentBody
            }
            ScrubBlockKind::ContentChunk { .. } => MountedContentChecksumLayer::EncodedContentChunk,
        };
        ScrubBlockEvidence {
            plaintext_identity: ScrubPlaintextIdentity {
                block_id,
                expected_plaintext_len: 4096,
                observed_plaintext_len: None,
            },
            checksum_layer: Some(crate::types::MountedContentChecksumEvidence {
                layer: checksum_layer,
                expected: Some(expected),
                actual,
                encoded_len: 4096,
            }),
            placement_evidence,
            raw_media_diagnostic: ScrubRawMediaDiagnostic {
                object_key_hex: Some("test-object".to_string()),
                reason: None,
            },
        }
    }

    #[test]
    fn convert_corrupt_violation_to_suspect_entry() {
        let mut report = ScrubReport::empty();
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 100,
                data_version: 3,
                kind: ScrubBlockKind::ContentChunk { chunk_index: 5 },
            },
            key_hex: "64".into(),
            outcome: ScrubBlockOutcome::Corrupt {
                expected: IntegrityDigest64(0xDEADBEEF),
                actual: IntegrityDigest64(0xCAFEBABE),
            },
        });

        let entries = repair_input_entries(&report);
        assert_eq!(entries.len(), 1);

        let e = &entries[0];
        assert_eq!(e.locator_id, 100);
        assert_eq!(e.segment_id, 3);
        assert_eq!(e.offset, 5);
        assert_eq!(e.record_type, 1u8); // payload corruption
        assert!(!e.resolved);
        assert_eq!(e.repair_attempts, 0);
    }

    #[test]
    fn convert_corrupt_violation_attaches_mounted_scrub_evidence() {
        let mut report = ScrubReport::empty();
        let block_id = ScrubBlockId {
            inode_id: 101,
            data_version: 4,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 6 },
        };
        let expected = IntegrityDigest64(0xABCD);
        let actual = IntegrityDigest64(0x1234);
        report.block_evidence.insert(
            block_id.clone(),
            mounted_scrub_block_evidence(block_id.clone(), expected, actual, 9),
        );
        report.violations.push(ScrubViolation {
            block_id,
            key_hex: "65".into(),
            outcome: ScrubBlockOutcome::Corrupt { expected, actual },
        });

        let inputs = convert_violations_to_repair_inputs(&report);

        assert_eq!(inputs.len(), 1);
        let receipt = inputs[0].placement_receipt_ref.expect("placement receipt");
        assert_eq!(receipt.object_id, 101);
        assert_eq!(receipt.receipt_generation, 9);
        assert_eq!(receipt.payload_digest, digest64_bytes(expected));
        assert_eq!(receipt.target_count, 2);
        let evidence = inputs[0]
            .mounted_scrub_evidence
            .expect("mounted scrub evidence");
        assert_eq!(
            evidence.subject,
            RepairCandidateIdentity::new(101, 4, RepairBlockKind::ContentChunk { chunk_index: 6 })
        );
        assert_eq!(evidence.checksum.expected, Some(digest64_bytes(expected)));
        assert_eq!(evidence.checksum.actual, digest64_bytes(actual));
        assert_eq!(
            evidence.receipt_status,
            RepairMountedReceiptEvidenceStatus::ReceiptVerified { generation: 9 }
        );
    }

    #[test]
    fn convert_non_verified_mounted_receipt_evidence_remains_receiptless() {
        let states = [
            MountedContentPlacementEvidence::SparseHole,
            MountedContentPlacementEvidence::ReceiptObservedButUnbound { generation: 7 },
            MountedContentPlacementEvidence::ReceiptMissing {
                expected_generation: Some(8),
            },
            MountedContentPlacementEvidence::ReceiptStale {
                expected_generation: 9,
                observed_generation: 6,
            },
            MountedContentPlacementEvidence::ReceiptUnavailable {
                expected_generation: None,
            },
        ];

        for (i, placement_evidence) in states.into_iter().enumerate() {
            let mut report = ScrubReport::empty();
            let block_id = ScrubBlockId {
                inode_id: 120 + i as u64,
                data_version: 4,
                kind: ScrubBlockKind::InlineContent,
            };
            let expected = IntegrityDigest64(0xABCD + i as u64);
            let actual = IntegrityDigest64(0x1234 + i as u64);
            report.block_evidence.insert(
                block_id.clone(),
                mounted_scrub_block_evidence_with_placement(
                    block_id.clone(),
                    expected,
                    actual,
                    placement_evidence.clone(),
                ),
            );
            report.violations.push(ScrubViolation {
                block_id,
                key_hex: "78".into(),
                outcome: ScrubBlockOutcome::Corrupt { expected, actual },
            });

            let inputs = convert_violations_to_repair_inputs(&report);

            assert_eq!(inputs.len(), 1);
            assert_eq!(inputs[0].placement_receipt_ref, None);
            assert_eq!(
                inputs[0]
                    .mounted_scrub_evidence
                    .expect("mounted evidence")
                    .receipt_status,
                repair_receipt_status_from_mounted(&placement_evidence)
            );
        }
    }

    #[test]
    fn convert_single_copy_mounted_receipt_evidence_remains_receiptless() {
        let mut report = ScrubReport::empty();
        let block_id = ScrubBlockId {
            inode_id: 140,
            data_version: 5,
            kind: ScrubBlockKind::InlineContent,
        };
        let expected = IntegrityDigest64(0xC0FFEE);
        let actual = IntegrityDigest64(0xBAD);
        let placement_evidence = MountedContentPlacementEvidence::ReceiptVerified {
            generation: 12,
            placement_receipt_ref: placement_receipt_ref_for_evidence(&block_id, expected, 12, 1),
        };
        report.block_evidence.insert(
            block_id.clone(),
            mounted_scrub_block_evidence_with_placement(
                block_id.clone(),
                expected,
                actual,
                placement_evidence,
            ),
        );
        report.violations.push(ScrubViolation {
            block_id,
            key_hex: "8c".into(),
            outcome: ScrubBlockOutcome::Corrupt { expected, actual },
        });

        let inputs = convert_violations_to_repair_inputs(&report);

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].placement_receipt_ref, None);
        assert_eq!(
            inputs[0]
                .mounted_scrub_evidence
                .expect("mounted evidence")
                .receipt_status,
            RepairMountedReceiptEvidenceStatus::ReceiptVerified { generation: 12 }
        );
    }

    #[test]
    fn convert_mounted_receipt_ref_mismatches_remain_receiptless() {
        let block_id = ScrubBlockId {
            inode_id: 141,
            data_version: 5,
            kind: ScrubBlockKind::InlineContent,
        };
        let expected = IntegrityDigest64(0xC0FFEE);
        let actual = IntegrityDigest64(0xBAD);
        let base_receipt = placement_receipt_ref_for_evidence(&block_id, expected, 14, 2);
        let mut object_id_mismatch = base_receipt;
        object_id_mismatch.object_id += 1;
        let mut payload_len_mismatch = base_receipt;
        payload_len_mismatch.payload_len += 1;
        let mut payload_digest_mismatch = base_receipt;
        payload_digest_mismatch.payload_digest[0] ^= 0xFF;
        let mut synthetic_generation = base_receipt;
        synthetic_generation.receipt_generation = 0;
        let mut policy_width_mismatch = base_receipt;
        policy_width_mismatch.target_count += 1;
        let cases = [
            object_id_mismatch,
            payload_len_mismatch,
            payload_digest_mismatch,
            synthetic_generation,
            policy_width_mismatch,
        ];

        for (i, placement_receipt_ref) in cases.into_iter().enumerate() {
            let mut report = ScrubReport::empty();
            report.block_evidence.insert(
                block_id.clone(),
                mounted_scrub_block_evidence_with_placement(
                    block_id.clone(),
                    expected,
                    actual,
                    MountedContentPlacementEvidence::ReceiptVerified {
                        generation: placement_receipt_ref.receipt_generation,
                        placement_receipt_ref,
                    },
                ),
            );
            report.violations.push(ScrubViolation {
                block_id: block_id.clone(),
                key_hex: format!("8c-{i}"),
                outcome: ScrubBlockOutcome::Corrupt { expected, actual },
            });

            let inputs = convert_violations_to_repair_inputs(&report);

            assert_eq!(inputs.len(), 1);
            assert_eq!(inputs[0].placement_receipt_ref, None);
            assert_eq!(
                inputs[0]
                    .mounted_scrub_evidence
                    .as_ref()
                    .expect("mounted evidence")
                    .receipt_status,
                RepairMountedReceiptEvidenceStatus::ReceiptVerified {
                    generation: placement_receipt_ref.receipt_generation
                }
            );
        }
    }

    #[test]
    fn convert_mismatched_mounted_subject_receipt_remains_receiptless() {
        let mut report = ScrubReport::empty();
        let violation_block_id = ScrubBlockId {
            inode_id: 142,
            data_version: 5,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 7 },
        };
        let evidence_block_id = ScrubBlockId {
            inode_id: 142,
            data_version: 5,
            kind: ScrubBlockKind::ContentChunk { chunk_index: 8 },
        };
        let expected = IntegrityDigest64(0xC0FFEE);
        let actual = IntegrityDigest64(0xBAD);

        report.block_evidence.insert(
            violation_block_id.clone(),
            mounted_scrub_block_evidence(evidence_block_id, expected, actual, 13),
        );
        report.violations.push(ScrubViolation {
            block_id: violation_block_id,
            key_hex: "8d".into(),
            outcome: ScrubBlockOutcome::Corrupt { expected, actual },
        });

        let inputs = convert_violations_to_repair_inputs(&report);

        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].placement_receipt_ref, None);
        assert_eq!(
            inputs[0]
                .mounted_scrub_evidence
                .as_ref()
                .expect("mounted evidence")
                .receipt_status,
            RepairMountedReceiptEvidenceStatus::ReceiptVerified { generation: 13 }
        );
    }

    #[test]
    fn report_backed_mounted_receipt_queues_and_dispatches_repair() {
        let inode_id = 512;
        let data_version = 1;
        let block_id = ScrubBlockId {
            inode_id,
            data_version,
            kind: ScrubBlockKind::InlineContent,
        };
        let expected = IntegrityDigest64(0xAA);
        let actual = IntegrityDigest64(0xBB);
        let mut report = ScrubReport::empty();
        report.block_evidence.insert(
            block_id.clone(),
            mounted_scrub_block_evidence(block_id.clone(), expected, actual, 1),
        );
        report.violations.push(ScrubViolation {
            block_id,
            key_hex: "200".into(),
            outcome: ScrubBlockOutcome::Corrupt { expected, actual },
        });

        let mut inputs = convert_violations_to_repair_inputs(&report);
        assert_eq!(inputs.len(), 1);
        let source_receipt = inputs[0].placement_receipt_ref.expect("source receipt");
        let comparison =
            comparison_record_for_entry(&inputs[0].entry, RepairBlockKind::InlineContent);
        inputs[0] = inputs[0].with_cross_replica_comparison(&comparison);

        let mut state = crate::recovery::initial_state();
        insert_inode(&mut state, make_file_inode(inode_id, data_version, 4096));
        let mut store = temp_store();
        let key = crate::object_keys::content_object_key_for_version(
            InodeId::new(inode_id),
            data_version,
        );
        let (raw, payload) = encoded_reconstructable_object();
        store.put(key, &raw).expect("store corrupt EC object");

        let mut bridge = ScrubToRepairBridge::new();
        let admissions = bridge.ingest_with_evidence(&inputs, 1);
        assert_eq!(admissions.len(), 1);
        assert_eq!(bridge.pending_count(), 1);

        let applied =
            dispatch_repair_from_bridge(&mut bridge, &mut state, &mut store, &mut BTreeMap::new());

        assert_eq!(applied.len(), 1);
        let crate::repair::RepairOutcome::Reconstructed {
            ref replacement_receipt,
            ..
        } = applied.entries[0].outcome
        else {
            panic!(
                "expected reconstructed receipt outcome, got {:?}",
                applied.entries[0].outcome
            );
        };
        assert_eq!(
            replacement_receipt.source_placement_receipt_ref,
            source_receipt
        );
        assert_eq!(
            replacement_receipt.replacement_receipt_generation(),
            source_receipt.receipt_generation + 1
        );
        assert_eq!(
            applied.entries[0]
                .outcome
                .replacement_receipt_evidence()
                .expect("replacement evidence")
                .downstream_evidence(),
            replacement_receipt.downstream_evidence()
        );
        assert_eq!(store.get(key).expect("read key").expect("stored"), payload);
        assert_eq!(bridge.repaired_count(), 1);
        assert_eq!(bridge.pending_count(), 0);
    }

    #[test]
    fn convert_unreadable_violation_to_suspect_entry() {
        let mut report = ScrubReport::empty();
        report.violations.push(ScrubViolation {
            block_id: ScrubBlockId {
                inode_id: 200,
                data_version: 1,
                kind: ScrubBlockKind::InlineContent,
            },
            key_hex: "c8".into(),
            outcome: ScrubBlockOutcome::Unreadable("disk sector bad".into()),
        });

        let entries = repair_input_entries(&report);
        assert_eq!(entries.len(), 1);

        let e = &entries[0];
        assert_eq!(e.locator_id, 200);
        assert_eq!(e.record_type, 3u8); // unreadable
        assert_eq!(e.expected_hash, [0u8; 32]);
        assert_eq!(e.actual_hash, [0u8; 32]);
    }

    #[test]
    fn convert_empty_report_returns_no_entries() {
        let report = ScrubReport::empty();
        let entries = repair_input_entries(&report);
        assert!(entries.is_empty());
    }

    // ── repair_job_to_violation tests ──────────────────────────────

    #[test]
    fn repair_job_to_violation_maps_fields() {
        use tidefs_local_object_store::SuspectEntry;

        let suspect = SuspectEntry {
            entry_id: 0,
            locator_id: 77,
            segment_id: 2,
            offset: 3,
            record_type: 1, // corrupt
            expected_hash: {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&0xCAFEu64.to_le_bytes());
                h
            },
            actual_hash: {
                let mut h = [0u8; 32];
                h[..8].copy_from_slice(&0xBABEu64.to_le_bytes());
                h
            },
            repair_attempts: 0,
            last_repair_attempt: 0,
            resolved: false,
            commit_group: 0,
            timestamp_secs: 0,
        };

        use tidefs_scrub::repair_scheduling::{RepairEvidence, RepairJob};

        let receipt = receipt_for_entry(&suspect);
        let mounted = mounted_scrub_evidence_for_entry(
            &suspect,
            RepairBlockKind::ContentChunk {
                chunk_index: suspect.offset,
            },
            receipt.receipt_generation,
        );
        let evidence = RepairEvidence::from_placement_receipt(&suspect, receipt, mounted)
            .expect("test receipt should admit repair job");
        let identity = RepairCandidateIdentity::new(
            suspect.locator_id,
            suspect.segment_id,
            RepairBlockKind::ContentChunk {
                chunk_index: suspect.offset,
            },
        );
        let job = RepairJob::new_with_identity(suspect, evidence, identity, 0);

        let violation = repair_job_to_violation(&job);
        assert_eq!(violation.block_id.inode_id, 77);
        assert_eq!(violation.block_id.data_version, 2);

        // ContentChunk since offset > 0.
        match &violation.block_id.kind {
            ScrubBlockKind::ContentChunk { chunk_index } => assert_eq!(*chunk_index, 3),
            _ => panic!("expected ContentChunk"),
        }

        match &violation.outcome {
            ScrubBlockOutcome::Corrupt { expected, actual } => {
                assert_eq!(expected.0, 0xCAFE);
                assert_eq!(actual.0, 0xBABE);
            }
            _ => panic!("expected Corrupt outcome"),
        }
    }
}
