// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Deterministic cross-replica checksum comparison engine.
//!
//! Consumes per-replica evidence keyed by [`ScrubSubject`] and produces a
//! reconciled [`CrossReplicaComparisonRecord`] that repair dispatch can
//! consume without re-running transport fanout.
//!
//! This module implements the comparison authority defined by
//! `docs/CROSS_REPLICA_SCRUB_COMPARISON_DESIGN.md` (#738/#757).  It rejects
//! evidence whose subject identity, receipt evidence, checksum layer, epoch,
//! or policy does not match the comparison candidate, then classifies the
//! surviving evidence into one of the required reconciliation outcomes.
//!
//! This module does **not** implement transport framing, network I/O, repair
//! writeback, or local-filesystem mutation.

#![forbid(unsafe_code)]

// ---------------------------------------------------------------------------
// Comparison subject identity
// ---------------------------------------------------------------------------

/// Stable scrub-subject identity for mounted content.
///
/// Mirrors the `ScrubBlockId` concept from `tidefs_local_filesystem` while
/// keeping `tidefs-scrub-core` self-contained for comparison purposes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ScrubSubject {
    pub inode_id: u64,
    pub data_version: u64,
    pub kind: ScrubSubjectKind,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ScrubSubjectKind {
    InlineContent,
    ContentManifest,
    ContentChunk { chunk_index: u64 },
}

// ---------------------------------------------------------------------------
// Checksum layer
// ---------------------------------------------------------------------------

/// Checksum-layer namespace for evidence comparison.
///
/// Evidence from different layers is not comparable without an explicit
/// mapping; the engine rejects cross-layer evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ChecksumLayer {
    InlineContentBody,
    EncodedContentChunk,
    SparseHole,
}

// ---------------------------------------------------------------------------
// Comparison candidate
// ---------------------------------------------------------------------------

/// A fully-qualified comparison candidate: the subject, its receipt-bound
/// identity, and the epoch/generation evidence required to prove every
/// replica is talking about the same bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComparisonCandidate {
    pub subject: ScrubSubject,
    /// 32-byte content object key bound to the placement receipt.
    pub object_key: [u8; 32],
    /// Checksum layer under which evidence is being compared.
    pub checksum_layer: ChecksumLayer,
    /// Receipt-bound expected digest, when the receipt declares one.
    pub expected_checksum: Option<[u8; 32]>,
    /// Placement-receipt epoch recorded in the receipt.
    pub placement_receipt_epoch: u64,
    /// Monotonic receipt write generation.
    pub placement_receipt_generation: u64,
    /// Membership epoch used to authorise the target set.
    pub membership_epoch: u64,
    /// Redundancy-policy identity in force for this placement.
    pub redundancy_policy_id: u8,
    /// Number of physical targets declared by the placement receipt.
    pub target_count: u16,
}

// ---------------------------------------------------------------------------
// Per-replica evidence
// ---------------------------------------------------------------------------

/// Outcome observed when one replica read the comparison subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EvidenceReadOutcome {
    /// Local read matched the expected checksum.
    Clean { checksum: [u8; 32] },
    /// Local checksum differs from the expected checksum.
    Mismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Object not found on this replica.
    Missing,
    /// Object present but unrecoverable (e.g. I/O error).
    Unreadable,
    /// Object exists but has no checksum evidence for the requested layer.
    NoChecksum,
    /// Receipt carried by the request is stale on this replica.
    ReceiptStale,
    /// Transport-level failure prevented evidence collection.
    TransportFailure { reason: TransportFailureReason },
}

/// Why transport could not deliver evidence from a peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportFailureReason {
    Unreachable,
    Backpressured,
    EpochRejected,
    Timeout,
    SessionClosed,
}

/// Evidence contributed by one replica for a single comparison candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReplicaEvidence {
    /// Replica identifier (membership node id).
    pub replica_id: u64,
    /// Scrub subject this replica is reporting about.
    pub subject: ScrubSubject,
    /// Object key observed by this replica.
    pub object_key: [u8; 32],
    /// Checksum layer used for this evidence.
    pub checksum_layer: ChecksumLayer,
    /// Redundancy-policy identity observed with this evidence.
    pub redundancy_policy_id: u8,
    /// Number of receipt targets observed with this evidence.
    pub target_count: u16,
    /// Content generation observed by this replica's local filesystem.
    pub content_generation: u64,
    /// Placement receipt epoch seen by this replica.
    pub placement_receipt_epoch: u64,
    /// Placement receipt generation seen by this replica.
    pub placement_receipt_generation: u64,
    /// Membership epoch under which this replica was contacted.
    pub membership_epoch: u64,
    /// Freshness epoch of this evidence (source epoch when the read occurred).
    pub source_epoch: u64,
    /// Read outcome observed by this replica.
    pub read_outcome: EvidenceReadOutcome,
}

// ---------------------------------------------------------------------------
// Evidence rejection reason
// ---------------------------------------------------------------------------

/// Why a particular piece of evidence was rejected from the comparison pool.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceRejectionReason {
    /// Subject identity (inode, data_version, kind) does not match.
    SubjectMismatch,
    /// Object key does not match the candidate.
    ObjectKeyMismatch,
    /// Checksum layer does not match the candidate.
    ChecksumLayerMismatch,
    /// Redundancy-policy identity does not match the candidate.
    RedundancyPolicyMismatch,
    /// Receipt target count does not match the candidate.
    TargetCountMismatch,
    /// Placement receipt epoch does not match.
    ReceiptEpochMismatch,
    /// Placement receipt generation does not match.
    ReceiptGenerationMismatch,
    /// Membership epoch does not match.
    MembershipEpochMismatch,
    /// Evidence is stale: content generation, receipt generation, or
    /// membership epoch is older than the candidate.
    StaleGeneration,
    /// Read outcome indicates a stale receipt.
    ReceiptStale,
}

// ---------------------------------------------------------------------------
// Per-replica recorded outcome
// ---------------------------------------------------------------------------

/// Outcome recorded for one replica after evidence acceptance/rejection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PerReplicaOutcome {
    pub replica_id: u64,
    /// Whether the evidence was accepted into the comparison pool.
    pub accepted: bool,
    /// If rejected, why.
    pub rejection_reason: Option<EvidenceRejectionReason>,
    /// The read outcome, if evidence was provided.
    pub read_outcome: Option<EvidenceReadOutcome>,
}

// ---------------------------------------------------------------------------
// Reconciliation classification
// ---------------------------------------------------------------------------

/// Reconciled cross-replica comparison result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ComparisonClassification {
    /// Every authoritative target reports the expected checksum.
    CleanAgreement,
    /// One replica reports mismatch/unreadable; every other target is clean.
    SingleReplicaCorruption {
        /// The corrupt replica id.
        corrupt_replica: u64,
        /// Clean replica ids that can serve as repair sources.
        clean_sources: Vec<u64>,
    },
    /// A remote replica is corrupt while the local replica is clean.
    RemoteReplicaCorruption {
        corrupt_replica: u64,
        clean_sources: Vec<u64>,
    },
    /// At least one authoritative target is missing evidence but the
    /// available clean set is still non-empty.
    IncompleteComparison {
        /// Targets for which no evidence was received.
        missing_targets: Vec<u64>,
    },
    /// Two or more replicas report non-expected checksum values, or replicas
    /// disagree about which checksum is correct.
    CrossReplicaDisagreement,
    /// All reachable replicas agree on a checksum that differs from the
    /// receipt or manifest expected checksum.
    ChecksumAuthorityDisagreement,
    /// One or more evidence items carry stale generation/epoch evidence.
    StaleEvidence {
        /// Replicas whose evidence was rejected as stale.
        stale_replicas: Vec<u64>,
    },
    /// A current receipt target returned NoChecksum for a block that
    /// requires checksum evidence.
    MissingChecksumEvidence { replicas_without_checksum: Vec<u64> },
    /// A current receipt target is unreachable, backpressured, or
    /// epoch-rejected, and no clean replica set can be confirmed.
    MissingReplicaEvidence { missing_targets: Vec<u64> },
}

// ---------------------------------------------------------------------------
// Comparison record
// ---------------------------------------------------------------------------

/// Deterministic cross-replica comparison record.
///
/// Produced by [`compare_cross_replica`] and consumed by repair dispatch.
/// Contains the full comparison identity, per-replica outcomes, reconciled
/// classification, and source/target sets where applicable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CrossReplicaComparisonRecord {
    pub subject: ScrubSubject,
    pub object_key: [u8; 32],
    pub checksum_layer: ChecksumLayer,
    pub redundancy_policy_id: u8,
    pub target_count: u16,
    pub placement_receipt_epoch: u64,
    pub placement_receipt_generation: u64,
    pub membership_epoch: u64,
    /// Per-replica outcomes in deterministic order (by replica_id).
    pub replica_outcomes: Vec<PerReplicaOutcome>,
    /// Reconciled classification.
    pub classification: ComparisonClassification,
    /// Clean source replica ids, when classification permits.
    pub clean_source_set: Vec<u64>,
    /// Corrupt target replica ids, when classification identifies them.
    pub corrupt_target_set: Vec<u64>,
}

// ---------------------------------------------------------------------------
// Comparison engine
// ---------------------------------------------------------------------------

/// Reconcile per-replica checksum evidence for one comparison candidate.
///
/// # Evidence rejection
///
/// Evidence is rejected when its subject, object key, checksum layer,
/// receipt epoch, receipt generation, or membership epoch does not match
/// the candidate.  Evidence whose generation/epoch is older than the
/// candidate is rejected as stale.
///
/// # Missing targets
///
/// Every id in `authoritative_target_ids` is expected to contribute
/// evidence.  Targets with no matching `ReplicaEvidence` are recorded as
/// missing.
///
/// # Determinism
///
/// Given identical inputs this function produces identical output records.
/// Evidence is sorted by `replica_id` before processing so the record is
/// independent of input ordering.
#[must_use]
pub fn compare_cross_replica(
    candidate: &ComparisonCandidate,
    evidence: &[ReplicaEvidence],
    authoritative_target_ids: &[u64],
) -> CrossReplicaComparisonRecord {
    let mut replica_outcomes: Vec<PerReplicaOutcome> = Vec::new();
    let mut accepted_evidence: Vec<&ReplicaEvidence> = Vec::new();
    let mut stale_replicas: Vec<u64> = Vec::new();
    let mut reported_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();

    // Sort evidence by replica_id for deterministic output.
    let mut sorted_evidence: Vec<&ReplicaEvidence> = evidence.iter().collect();
    sorted_evidence.sort_by_key(|e| e.replica_id);

    for ev in &sorted_evidence {
        reported_ids.insert(ev.replica_id);

        let rejection = evidence_rejection(ev, candidate);
        let outcome = PerReplicaOutcome {
            replica_id: ev.replica_id,
            accepted: rejection.is_none(),
            rejection_reason: rejection,
            read_outcome: Some(ev.read_outcome.clone()),
        };

        if rejection.is_none() {
            accepted_evidence.push(ev);
        } else if rejection == Some(EvidenceRejectionReason::StaleGeneration)
            || rejection == Some(EvidenceRejectionReason::ReceiptStale)
        {
            stale_replicas.push(ev.replica_id);
        }

        replica_outcomes.push(outcome);
    }

    // Identify missing authoritative targets.
    let missing_targets: Vec<u64> = authoritative_target_ids
        .iter()
        .copied()
        .filter(|id| !reported_ids.contains(id))
        .collect();

    // Record missing targets with no evidence at all.
    for &id in &missing_targets {
        replica_outcomes.push(PerReplicaOutcome {
            replica_id: id,
            accepted: false,
            rejection_reason: None,
            read_outcome: None,
        });
    }
    // Sort final outcomes by replica_id for determinism.
    replica_outcomes.sort_by_key(|o| o.replica_id);

    let classification = classify(
        candidate,
        &accepted_evidence,
        &stale_replicas,
        &missing_targets,
        authoritative_target_ids,
    );

    let (clean_source_set, corrupt_target_set) = source_target_sets(&classification);

    CrossReplicaComparisonRecord {
        subject: candidate.subject,
        object_key: candidate.object_key,
        checksum_layer: candidate.checksum_layer,
        redundancy_policy_id: candidate.redundancy_policy_id,
        target_count: candidate.target_count,
        placement_receipt_epoch: candidate.placement_receipt_epoch,
        placement_receipt_generation: candidate.placement_receipt_generation,
        membership_epoch: candidate.membership_epoch,
        replica_outcomes,
        classification,
        clean_source_set,
        corrupt_target_set,
    }
}

// ---------------------------------------------------------------------------
// Evidence rejection
// ---------------------------------------------------------------------------

fn evidence_rejection(
    evidence: &ReplicaEvidence,
    candidate: &ComparisonCandidate,
) -> Option<EvidenceRejectionReason> {
    // Identity checks: must match the candidate exactly.
    if evidence.subject != candidate.subject {
        return Some(EvidenceRejectionReason::SubjectMismatch);
    }
    if evidence.object_key != candidate.object_key {
        return Some(EvidenceRejectionReason::ObjectKeyMismatch);
    }
    if evidence.checksum_layer != candidate.checksum_layer {
        return Some(EvidenceRejectionReason::ChecksumLayerMismatch);
    }
    if evidence.redundancy_policy_id != candidate.redundancy_policy_id {
        return Some(EvidenceRejectionReason::RedundancyPolicyMismatch);
    }
    if evidence.target_count != candidate.target_count {
        return Some(EvidenceRejectionReason::TargetCountMismatch);
    }
    if evidence.placement_receipt_epoch != candidate.placement_receipt_epoch {
        return Some(EvidenceRejectionReason::ReceiptEpochMismatch);
    }
    // Stale receipt generation (older) is StaleEvidence, not a mismatch.
    if evidence.placement_receipt_generation > candidate.placement_receipt_generation {
        return Some(EvidenceRejectionReason::ReceiptGenerationMismatch);
    }
    // Stale membership epoch (older) is StaleEvidence, not a mismatch.
    if evidence.membership_epoch > candidate.membership_epoch {
        return Some(EvidenceRejectionReason::MembershipEpochMismatch);
    }

    // Staleness: generation/epoch older than the candidate.
    if evidence.content_generation < candidate.subject.data_version
        || evidence.placement_receipt_generation < candidate.placement_receipt_generation
        || evidence.membership_epoch < candidate.membership_epoch
    {
        return Some(EvidenceRejectionReason::StaleGeneration);
    }

    // Evidence that is receipt-stale.
    if matches!(&evidence.read_outcome, EvidenceReadOutcome::ReceiptStale) {
        return Some(EvidenceRejectionReason::ReceiptStale);
    }

    None
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

fn classify(
    candidate: &ComparisonCandidate,
    accepted: &[&ReplicaEvidence],
    stale_replicas: &[u64],
    missing_targets: &[u64],
    authoritative_target_ids: &[u64],
) -> ComparisonClassification {
    // If every piece of evidence was rejected as stale and there are missing
    // targets, the comparison is incomplete due to stale evidence.
    if accepted.is_empty() && !stale_replicas.is_empty() {
        return ComparisonClassification::StaleEvidence {
            stale_replicas: stale_replicas.to_vec(),
        };
    }

    // If any authoritative target is missing and no evidence was accepted,
    // report missing replica evidence.
    if accepted.is_empty() && !missing_targets.is_empty() {
        return ComparisonClassification::MissingReplicaEvidence {
            missing_targets: missing_targets.to_vec(),
        };
    }

    // At this point accepted is non-empty (or we've already returned).

    // Check for NoChecksum among accepted evidence.
    let no_checksum: Vec<u64> = accepted
        .iter()
        .filter(|e| matches!(&e.read_outcome, EvidenceReadOutcome::NoChecksum))
        .map(|e| e.replica_id)
        .collect();
    if !no_checksum.is_empty() {
        return ComparisonClassification::MissingChecksumEvidence {
            replicas_without_checksum: no_checksum,
        };
    }

    // Collect clean replicas (those reporting Clean with a checksum).
    let clean: Vec<&ReplicaEvidence> = accepted
        .iter()
        .filter(|e| matches!(&e.read_outcome, EvidenceReadOutcome::Clean { .. }))
        .copied()
        .collect();

    // Collect mismatch replicas.
    let mismatches: Vec<&ReplicaEvidence> = accepted
        .iter()
        .filter(|e| {
            matches!(
                &e.read_outcome,
                EvidenceReadOutcome::Mismatch { .. } | EvidenceReadOutcome::Unreadable
            )
        })
        .copied()
        .collect();

    if let Some(expected) = candidate.expected_checksum {
        let mismatch_expected_disagreement = mismatches.iter().any(|e| {
            matches!(
                &e.read_outcome,
                EvidenceReadOutcome::Mismatch {
                    expected: reported,
                    ..
                } if *reported != expected
            )
        });
        if mismatch_expected_disagreement {
            return ComparisonClassification::CrossReplicaDisagreement;
        }
    }

    // Missing objects and transport failures are evidence gaps, not clean
    // agreement. Preserve them alongside wholly absent target evidence.
    let unavailable_replicas: Vec<u64> = accepted
        .iter()
        .filter(|e| {
            matches!(
                &e.read_outcome,
                EvidenceReadOutcome::Missing | EvidenceReadOutcome::TransportFailure { .. }
            )
        })
        .map(|e| e.replica_id)
        .collect();
    let mut missing_or_unavailable_targets: Vec<u64> = missing_targets.to_vec();
    missing_or_unavailable_targets.extend(unavailable_replicas.iter().copied());
    missing_or_unavailable_targets.sort_unstable();
    missing_or_unavailable_targets.dedup();

    // If unavailable replicas leave no clean set, treat the comparison as
    // missing evidence rather than a checksum disagreement.
    if !unavailable_replicas.is_empty() && clean.is_empty() {
        return ComparisonClassification::MissingReplicaEvidence {
            missing_targets: missing_or_unavailable_targets,
        };
    }

    // Inspect checksum agreement among clean replicas.
    if let Some(ref expected) = candidate.expected_checksum {
        // Collect the set of checksums reported by clean replicas.
        let mut checksums_seen: std::collections::BTreeSet<[u8; 32]> =
            std::collections::BTreeSet::new();
        for ev in &clean {
            if let EvidenceReadOutcome::Clean { checksum } = &ev.read_outcome {
                checksums_seen.insert(*checksum);
            }
        }

        // All clean replicas agree on a checksum that differs from expected.
        if checksums_seen.len() == 1 && !checksums_seen.contains(expected) {
            return ComparisonClassification::ChecksumAuthorityDisagreement;
        }

        // Multiple different checksums among clean replicas.
        if checksums_seen.len() > 1 {
            return ComparisonClassification::CrossReplicaDisagreement;
        }
    }

    // Now classify based on mismatch count vs clean count.

    if mismatches.is_empty() && !clean.is_empty() {
        // All accepted evidence is clean, but check for missing targets.
        if !missing_or_unavailable_targets.is_empty() {
            return ComparisonClassification::IncompleteComparison {
                missing_targets: missing_or_unavailable_targets,
            };
        }

        // Check for stale replicas alongside clean agreement.
        if !stale_replicas.is_empty() {
            return ComparisonClassification::StaleEvidence {
                stale_replicas: stale_replicas.to_vec(),
            };
        }

        return ComparisonClassification::CleanAgreement;
    }

    if mismatches.len() == 1 && !clean.is_empty() {
        let corrupt_id = mismatches[0].replica_id;
        let clean_source_ids: Vec<u64> = clean.iter().map(|e| e.replica_id).collect();

        // If there are also missing targets, report incomplete.
        if !missing_or_unavailable_targets.is_empty() {
            return ComparisonClassification::IncompleteComparison {
                missing_targets: missing_or_unavailable_targets,
            };
        }

        // Determine if the mismatch is the local replica or a remote.
        // The local replica is the first authoritative target by convention.
        let local_id = authoritative_target_ids.first().copied();
        if local_id == Some(corrupt_id) {
            return ComparisonClassification::SingleReplicaCorruption {
                corrupt_replica: corrupt_id,
                clean_sources: clean_source_ids,
            };
        }

        return ComparisonClassification::RemoteReplicaCorruption {
            corrupt_replica: corrupt_id,
            clean_sources: clean_source_ids,
        };
    }

    // Multiple mismatches, or mismatches but no clean source.
    if mismatches.len() >= 2 || (mismatches.len() == 1 && clean.is_empty()) {
        return ComparisonClassification::CrossReplicaDisagreement;
    }

    // Fallthrough: no clean and no mismatch (e.g., all missing or transport
    // failures already handled). This shouldn't be reached but is defensive.
    ComparisonClassification::CrossReplicaDisagreement
}

// ---------------------------------------------------------------------------
// Source / target set extraction
// ---------------------------------------------------------------------------

fn source_target_sets(classification: &ComparisonClassification) -> (Vec<u64>, Vec<u64>) {
    match classification {
        ComparisonClassification::SingleReplicaCorruption {
            corrupt_replica,
            clean_sources,
        } => (clean_sources.clone(), vec![*corrupt_replica]),
        ComparisonClassification::RemoteReplicaCorruption {
            corrupt_replica,
            clean_sources,
        } => (clean_sources.clone(), vec![*corrupt_replica]),
        _ => (Vec::new(), Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn subject(kind: ScrubSubjectKind, version: u64) -> ScrubSubject {
        ScrubSubject {
            inode_id: 100,
            data_version: version,
            kind,
        }
    }

    fn inline_subject() -> ScrubSubject {
        subject(ScrubSubjectKind::InlineContent, 5)
    }

    fn candidate(subject: ScrubSubject) -> ComparisonCandidate {
        ComparisonCandidate {
            subject,
            object_key: [0xAAu8; 32],
            checksum_layer: ChecksumLayer::EncodedContentChunk,
            expected_checksum: Some([0xBBu8; 32]),
            placement_receipt_epoch: 3,
            placement_receipt_generation: 7,
            membership_epoch: 10,
            redundancy_policy_id: 1,
            target_count: 3,
        }
    }

    fn clean_evidence(replica_id: u64, cand: &ComparisonCandidate) -> ReplicaEvidence {
        ReplicaEvidence {
            replica_id,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }
    }

    fn mismatch_evidence(
        replica_id: u64,
        cand: &ComparisonCandidate,
        expected: [u8; 32],
        actual: [u8; 32],
    ) -> ReplicaEvidence {
        ReplicaEvidence {
            replica_id,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Mismatch { expected, actual },
        }
    }

    // ------------------------------------------------------------------
    // CleanAgreement
    // ------------------------------------------------------------------

    #[test]
    fn all_replicas_agree_clean() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            clean_evidence(1, &cand),
            clean_evidence(2, &cand),
            clean_evidence(3, &cand),
        ];
        let targets = vec![1, 2, 3];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::CleanAgreement
        );
        assert_eq!(record.redundancy_policy_id, cand.redundancy_policy_id);
        assert_eq!(record.target_count, cand.target_count);
        assert!(record.clean_source_set.is_empty());
        assert!(record.corrupt_target_set.is_empty());
        assert_eq!(record.replica_outcomes.len(), 3);
        for outcome in &record.replica_outcomes {
            assert!(outcome.accepted);
            assert!(outcome.rejection_reason.is_none());
        }
    }

    // ------------------------------------------------------------------
    // SingleReplicaCorruption – local mismatch
    // ------------------------------------------------------------------

    #[test]
    fn single_replica_corruption_local() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            mismatch_evidence(1, &cand, cand.expected_checksum.unwrap(), [0xCCu8; 32]),
            clean_evidence(2, &cand),
            clean_evidence(3, &cand),
        ];
        // Replica 1 is first in authoritative list → treated as local.
        let targets = vec![1, 2, 3];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::SingleReplicaCorruption {
                corrupt_replica: 1,
                clean_sources: vec![2, 3],
            }
        );
        assert_eq!(record.clean_source_set, vec![2, 3]);
        assert_eq!(record.corrupt_target_set, vec![1]);
    }

    // ------------------------------------------------------------------
    // RemoteReplicaCorruption – remote mismatch
    // ------------------------------------------------------------------

    #[test]
    fn remote_replica_corruption() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            clean_evidence(1, &cand),
            mismatch_evidence(2, &cand, cand.expected_checksum.unwrap(), [0xCCu8; 32]),
            clean_evidence(3, &cand),
        ];
        // Replica 1 is first → local is clean; replica 2 is remote corrupt.
        let targets = vec![1, 2, 3];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::RemoteReplicaCorruption {
                corrupt_replica: 2,
                clean_sources: vec![1, 3],
            }
        );
        assert_eq!(record.clean_source_set, vec![1, 3]);
        assert_eq!(record.corrupt_target_set, vec![2]);
    }

    // ------------------------------------------------------------------
    // CrossReplicaDisagreement
    // ------------------------------------------------------------------

    #[test]
    fn two_mismatches_disagreement() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            mismatch_evidence(1, &cand, cand.expected_checksum.unwrap(), [0xCCu8; 32]),
            mismatch_evidence(2, &cand, cand.expected_checksum.unwrap(), [0xDDu8; 32]),
        ];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::CrossReplicaDisagreement
        );
    }

    #[test]
    fn mismatch_expected_checksum_disagreement() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            clean_evidence(1, &cand),
            mismatch_evidence(2, &cand, [0xEEu8; 32], [0xCCu8; 32]),
        ];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::CrossReplicaDisagreement
        );
    }

    #[test]
    fn mismatch_without_clean_source_disagreement() {
        let cand = candidate(inline_subject());
        let evidence = vec![mismatch_evidence(
            1,
            &cand,
            cand.expected_checksum.unwrap(),
            [0xCCu8; 32],
        )];
        let targets = vec![1, 2, 3]; // other targets missing

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::CrossReplicaDisagreement
        );
    }

    // ------------------------------------------------------------------
    // ChecksumAuthorityDisagreement
    // ------------------------------------------------------------------

    #[test]
    fn all_agree_on_wrong_checksum() {
        let cand = candidate(inline_subject());
        let wrong_checksum = [0xEEu8; 32];
        // All replicas report Clean but with a checksum that doesn't match
        // the candidate's expected_checksum.
        let evidence = vec![
            ReplicaEvidence {
                replica_id: 1,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::Clean {
                    checksum: wrong_checksum,
                },
            },
            ReplicaEvidence {
                replica_id: 2,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::Clean {
                    checksum: wrong_checksum,
                },
            },
        ];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::ChecksumAuthorityDisagreement
        );
    }

    // ------------------------------------------------------------------
    // StaleEvidence
    // ------------------------------------------------------------------

    #[test]
    fn stale_content_generation() {
        let cand = candidate(inline_subject()); // data_version = 5
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: 3, // older than candidate data_version 5
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::StaleEvidence {
                stale_replicas: vec![1],
            }
        );
        assert!(!record.replica_outcomes[0].accepted);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::StaleGeneration)
        );
    }

    #[test]
    fn stale_receipt_generation() {
        let cand = candidate(inline_subject()); // receipt_generation = 7
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: 5, // older than candidate 7
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::StaleEvidence {
                stale_replicas: vec![1],
            }
        );
    }

    // ------------------------------------------------------------------
    // Evidence rejection – mismatched identity
    // ------------------------------------------------------------------

    #[test]
    fn rejects_mismatched_subject() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: subject(ScrubSubjectKind::ContentChunk { chunk_index: 0 }, 5),
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert!(!record.replica_outcomes[0].accepted);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::SubjectMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_object_key() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: [0xFFu8; 32], // different key
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::ObjectKeyMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_checksum_layer() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: ChecksumLayer::InlineContentBody, // different
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::ChecksumLayerMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_redundancy_policy() {
        let cand = candidate(inline_subject());
        let mut evidence = clean_evidence(1, &cand);
        evidence.redundancy_policy_id = cand.redundancy_policy_id + 1;
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &[evidence], &targets);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::RedundancyPolicyMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_target_count() {
        let cand = candidate(inline_subject());
        let mut evidence = clean_evidence(1, &cand);
        evidence.target_count = cand.target_count + 1;
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &[evidence], &targets);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::TargetCountMismatch)
        );
    }

    #[test]
    fn rejects_mismatched_epoch() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: 99, // different
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::Clean {
                checksum: cand.expected_checksum.unwrap(),
            },
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::ReceiptEpochMismatch)
        );
    }

    // ------------------------------------------------------------------
    // MissingReplicaEvidence
    // ------------------------------------------------------------------

    #[test]
    fn missing_authoritative_target() {
        let cand = candidate(inline_subject());
        let evidence = vec![clean_evidence(1, &cand)]; // only replica 1
        let targets = vec![1, 2, 3]; // 2 and 3 are missing

        let record = compare_cross_replica(&cand, &evidence, &targets);
        // Accepted evidence exists (replica 1 is clean), but two targets
        // are missing → IncompleteComparison.
        assert_eq!(
            record.classification,
            ComparisonClassification::IncompleteComparison {
                missing_targets: vec![2, 3],
            }
        );
    }

    #[test]
    fn all_targets_missing_no_evidence() {
        let cand = candidate(inline_subject());
        let evidence: Vec<ReplicaEvidence> = vec![];
        let targets = vec![1, 2, 3];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::MissingReplicaEvidence {
                missing_targets: vec![1, 2, 3],
            }
        );
    }

    #[test]
    fn missing_read_outcome_is_not_clean_agreement() {
        let cand = candidate(inline_subject());
        let mut missing = clean_evidence(2, &cand);
        missing.read_outcome = EvidenceReadOutcome::Missing;
        let evidence = vec![clean_evidence(1, &cand), missing];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::IncompleteComparison {
                missing_targets: vec![2],
            }
        );
    }

    // ------------------------------------------------------------------
    // MissingChecksumEvidence
    // ------------------------------------------------------------------

    #[test]
    fn no_checksum_evidence() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::NoChecksum,
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::MissingChecksumEvidence {
                replicas_without_checksum: vec![1],
            }
        );
    }

    // ------------------------------------------------------------------
    // Determinism: output is independent of input ordering
    // ------------------------------------------------------------------

    #[test]
    fn deterministic_output_ordering() {
        let cand = candidate(inline_subject());
        let ev1 = clean_evidence(1, &cand);
        let ev2 = clean_evidence(2, &cand);
        let ev3 = clean_evidence(3, &cand);
        let targets = vec![1, 2, 3];

        let record_a =
            compare_cross_replica(&cand, &[ev3.clone(), ev1.clone(), ev2.clone()], &targets);
        let record_b =
            compare_cross_replica(&cand, &[ev1.clone(), ev2.clone(), ev3.clone()], &targets);

        assert_eq!(record_a, record_b);
    }

    // ------------------------------------------------------------------
    // IncompleteComparison – one clean, one mismatch, one missing
    // ------------------------------------------------------------------

    #[test]
    fn incomplete_with_mismatch_and_missing() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            clean_evidence(1, &cand),
            mismatch_evidence(2, &cand, cand.expected_checksum.unwrap(), [0xCCu8; 32]),
            // replica 3 is missing
        ];
        let targets = vec![1, 2, 3];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::IncompleteComparison {
                missing_targets: vec![3],
            }
        );
    }

    // ------------------------------------------------------------------
    // TransportFailure treated as missing when no clean source
    // ------------------------------------------------------------------

    #[test]
    fn transport_failure_all_unreachable() {
        let cand = candidate(inline_subject());
        let evidence = vec![
            ReplicaEvidence {
                replica_id: 1,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::TransportFailure {
                    reason: TransportFailureReason::Unreachable,
                },
            },
            ReplicaEvidence {
                replica_id: 2,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::TransportFailure {
                    reason: TransportFailureReason::Timeout,
                },
            },
        ];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::MissingReplicaEvidence {
                missing_targets: vec![1, 2],
            }
        );
    }

    #[test]
    fn transport_failure_with_clean_source_is_incomplete() {
        let cand = candidate(inline_subject());
        let mut transport_failure = clean_evidence(2, &cand);
        transport_failure.read_outcome = EvidenceReadOutcome::TransportFailure {
            reason: TransportFailureReason::Timeout,
        };
        let evidence = vec![clean_evidence(1, &cand), transport_failure];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::IncompleteComparison {
                missing_targets: vec![2],
            }
        );
    }

    // ------------------------------------------------------------------
    // ReceiptStale rejection
    // ------------------------------------------------------------------

    #[test]
    fn receipt_stale_rejection() {
        let cand = candidate(inline_subject());
        let evidence = vec![ReplicaEvidence {
            replica_id: 1,
            subject: cand.subject,
            object_key: cand.object_key,
            checksum_layer: cand.checksum_layer,
            redundancy_policy_id: cand.redundancy_policy_id,
            target_count: cand.target_count,
            content_generation: cand.subject.data_version,
            placement_receipt_epoch: cand.placement_receipt_epoch,
            placement_receipt_generation: cand.placement_receipt_generation,
            membership_epoch: cand.membership_epoch,
            source_epoch: 10,
            read_outcome: EvidenceReadOutcome::ReceiptStale,
        }];
        let targets = vec![1];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert!(!record.replica_outcomes[0].accepted);
        assert_eq!(
            record.replica_outcomes[0].rejection_reason,
            Some(EvidenceRejectionReason::ReceiptStale)
        );
        assert_eq!(
            record.classification,
            ComparisonClassification::StaleEvidence {
                stale_replicas: vec![1],
            }
        );
    }

    // ------------------------------------------------------------------
    // CrossReplicaDisagreement – clean replicas disagree on checksum
    // ------------------------------------------------------------------

    #[test]
    fn clean_replicas_disagree() {
        let cand = candidate(inline_subject());
        // Two clean replicas, but reporting different checksums.
        let evidence = vec![
            ReplicaEvidence {
                replica_id: 1,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::Clean {
                    checksum: [0x11u8; 32],
                },
            },
            ReplicaEvidence {
                replica_id: 2,
                subject: cand.subject,
                object_key: cand.object_key,
                checksum_layer: cand.checksum_layer,
                redundancy_policy_id: cand.redundancy_policy_id,
                target_count: cand.target_count,
                content_generation: cand.subject.data_version,
                placement_receipt_epoch: cand.placement_receipt_epoch,
                placement_receipt_generation: cand.placement_receipt_generation,
                membership_epoch: cand.membership_epoch,
                source_epoch: 10,
                read_outcome: EvidenceReadOutcome::Clean {
                    checksum: [0x22u8; 32],
                },
            },
        ];
        let targets = vec![1, 2];

        let record = compare_cross_replica(&cand, &evidence, &targets);
        assert_eq!(
            record.classification,
            ComparisonClassification::CrossReplicaDisagreement
        );
    }
}
