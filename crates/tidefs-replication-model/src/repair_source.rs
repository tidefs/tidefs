// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Repair-source receipt manifests for bounded replication model evidence.
//!
//! These receipts say which candidate source was considered for a repair,
//! which model/source evidence was required, and whether that source was
//! accepted or rejected. They do not schedule repairs, move bytes, validate a
//! remote node at runtime, or make distributed repair-safety claims.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use tidefs_membership_epoch::{ClusterMemberRecord, EpochId, MemberId, MembershipConfigRecord};

/// Dataset identity named by a repair-source receipt.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct RepairDatasetId(pub u64);

impl RepairDatasetId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

/// Object or extent identity named by a repair-source receipt.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RepairSourceSubject {
    /// Whole object identity.
    Object { object_id: u64 },
    /// Byte extent within an object.
    Extent {
        object_id: u64,
        offset: u64,
        len: u64,
    },
}

impl RepairSourceSubject {
    #[must_use]
    pub const fn object(object_id: u64) -> Self {
        Self::Object { object_id }
    }

    #[must_use]
    pub const fn extent(object_id: u64, offset: u64, len: u64) -> Self {
        Self::Extent {
            object_id,
            offset,
            len,
        }
    }
}

/// Freshness and membership-epoch metadata bound to a repair source.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairSourceFreshness {
    /// Membership epoch in which the source was considered.
    pub membership_epoch: EpochId,
    /// Source-local epoch or generation observed by the model evidence.
    pub source_epoch: u64,
    /// Monotonic frontier covered by the source evidence.
    pub observed_freshness_frontier: u64,
    /// Last membership epoch for which this receipt remains fresh.
    pub valid_until_epoch: EpochId,
}

impl RepairSourceFreshness {
    #[must_use]
    pub const fn new(
        membership_epoch: EpochId,
        source_epoch: u64,
        observed_freshness_frontier: u64,
        valid_until_epoch: EpochId,
    ) -> Self {
        Self {
            membership_epoch,
            source_epoch,
            observed_freshness_frontier,
            valid_until_epoch,
        }
    }
}

/// Evidence classes a receipt can require or provide.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RepairSourceEvidenceKind {
    /// Freshness fence or frontier evidence for the source.
    FreshnessFence,
    /// Membership epoch evidence for the source node.
    MembershipEpoch,
    /// Payload or extent digest evidence for the candidate source bytes.
    PayloadDigest,
    /// Placement or copy receipt evidence binding the source to the dataset.
    PlacementReceipt,
}

/// Source decision recorded in the receipt.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairSourceDecision {
    Accepted,
    Rejected,
}

/// Validation tier represented by the receipt.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RepairSourceValidationTier {
    /// Manifest-level source evidence only.
    ModelSourceEvidence,
    /// Local receipt and digest evidence were considered by the model.
    LocalReceiptDigest,
    /// Membership epoch and digest evidence were both considered by the model.
    MembershipEpochDigest,
}

/// Repair-source receipt manifest.
///
/// The manifest is intentionally a source-evidence artifact. It records the
/// candidate source, object/extent identity, digest evidence, freshness and
/// epoch bounds, validation tier, decision, and related claim/issue references.
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct RepairSourceReceiptManifest {
    pub source_node_id: MemberId,
    pub dataset_id: RepairDatasetId,
    pub subject: RepairSourceSubject,
    pub evidence_digest: Option<[u8; 32]>,
    pub freshness: RepairSourceFreshness,
    pub decision: RepairSourceDecision,
    pub validation_tier: RepairSourceValidationTier,
    pub required_evidence: BTreeSet<RepairSourceEvidenceKind>,
    pub provided_evidence: BTreeSet<RepairSourceEvidenceKind>,
    pub decision_reason_refs: BTreeSet<String>,
    pub related_claim_refs: BTreeSet<String>,
    pub related_issue_refs: BTreeSet<u64>,
}

impl RepairSourceReceiptManifest {
    pub fn verify(
        &self,
        context: &RepairSourceVerificationContext,
    ) -> Result<RepairSourceVerification, RepairSourceVerificationError> {
        RepairSourceReceiptVerifier::verify(self, context)
    }
}

/// Model snapshot used to verify repair-source receipts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepairSourceVerificationContext {
    pub expected_membership_epoch: EpochId,
    pub min_freshness_frontier: u64,
    pub known_source_ids: BTreeSet<MemberId>,
}

impl RepairSourceVerificationContext {
    #[must_use]
    pub fn new<I>(
        expected_membership_epoch: EpochId,
        min_freshness_frontier: u64,
        known_source_ids: I,
    ) -> Self
    where
        I: IntoIterator<Item = MemberId>,
    {
        Self {
            expected_membership_epoch,
            min_freshness_frontier,
            known_source_ids: known_source_ids.into_iter().collect(),
        }
    }

    /// Build a context from membership model records and source members.
    #[must_use]
    pub fn from_membership_records(
        config: &MembershipConfigRecord,
        members: &[ClusterMemberRecord],
        min_freshness_frontier: u64,
    ) -> Self {
        let known_source_ids = members
            .iter()
            .filter(|member| member.current_membership_epoch_ref == config.membership_epoch_id)
            .map(|member| member.member_id)
            .collect();
        Self {
            expected_membership_epoch: config.membership_epoch_id,
            min_freshness_frontier,
            known_source_ids,
        }
    }
}

/// Successful verification summary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RepairSourceVerification {
    pub source_node_id: MemberId,
    pub dataset_id: RepairDatasetId,
    pub subject: RepairSourceSubject,
    pub decision: RepairSourceDecision,
    pub validation_tier: RepairSourceValidationTier,
}

/// Errors returned by the repair-source receipt verifier.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RepairSourceVerificationError {
    #[error("unknown repair source node {source_node_id:?}")]
    UnknownSourceId { source_node_id: MemberId },
    #[error("repair source receipt epoch mismatch: expected {expected:?}, got {actual:?}")]
    MismatchedEpoch { expected: EpochId, actual: EpochId },
    #[error(
        "stale repair source receipt: frontier {observed_freshness_frontier} < {min_freshness_frontier} or valid_until {valid_until_epoch:?} < {expected_membership_epoch:?}"
    )]
    StaleReceipt {
        min_freshness_frontier: u64,
        observed_freshness_frontier: u64,
        valid_until_epoch: EpochId,
        expected_membership_epoch: EpochId,
    },
    #[error("repair source receipt is missing an evidence digest")]
    MissingEvidenceDigest,
    #[error("accepted repair source receipt has no required evidence")]
    AcceptedWithoutRequiredEvidence,
    #[error("accepted repair source receipt is missing required evidence {missing:?}")]
    MissingRequiredEvidence {
        missing: Vec<RepairSourceEvidenceKind>,
    },
}

/// Verifies repair-source receipt manifests against a bounded model context.
pub struct RepairSourceReceiptVerifier;

impl RepairSourceReceiptVerifier {
    pub fn verify(
        manifest: &RepairSourceReceiptManifest,
        context: &RepairSourceVerificationContext,
    ) -> Result<RepairSourceVerification, RepairSourceVerificationError> {
        if !context.known_source_ids.contains(&manifest.source_node_id) {
            return Err(RepairSourceVerificationError::UnknownSourceId {
                source_node_id: manifest.source_node_id,
            });
        }

        if manifest.freshness.membership_epoch != context.expected_membership_epoch {
            return Err(RepairSourceVerificationError::MismatchedEpoch {
                expected: context.expected_membership_epoch,
                actual: manifest.freshness.membership_epoch,
            });
        }

        if manifest.freshness.observed_freshness_frontier < context.min_freshness_frontier
            || manifest.freshness.valid_until_epoch < context.expected_membership_epoch
        {
            return Err(RepairSourceVerificationError::StaleReceipt {
                min_freshness_frontier: context.min_freshness_frontier,
                observed_freshness_frontier: manifest.freshness.observed_freshness_frontier,
                valid_until_epoch: manifest.freshness.valid_until_epoch,
                expected_membership_epoch: context.expected_membership_epoch,
            });
        }

        if manifest.evidence_digest.is_none() {
            return Err(RepairSourceVerificationError::MissingEvidenceDigest);
        }

        if manifest.decision == RepairSourceDecision::Accepted {
            if manifest.required_evidence.is_empty() {
                return Err(RepairSourceVerificationError::AcceptedWithoutRequiredEvidence);
            }
            let missing = manifest
                .required_evidence
                .difference(&manifest.provided_evidence)
                .copied()
                .collect::<Vec<_>>();
            if !missing.is_empty() {
                return Err(RepairSourceVerificationError::MissingRequiredEvidence { missing });
            }
        }

        Ok(RepairSourceVerification {
            source_node_id: manifest.source_node_id,
            dataset_id: manifest.dataset_id,
            subject: manifest.subject,
            decision: manifest.decision,
            validation_tier: manifest.validation_tier,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn required_evidence() -> BTreeSet<RepairSourceEvidenceKind> {
        BTreeSet::from([
            RepairSourceEvidenceKind::FreshnessFence,
            RepairSourceEvidenceKind::MembershipEpoch,
            RepairSourceEvidenceKind::PayloadDigest,
        ])
    }

    fn provided_evidence() -> BTreeSet<RepairSourceEvidenceKind> {
        BTreeSet::from([
            RepairSourceEvidenceKind::FreshnessFence,
            RepairSourceEvidenceKind::MembershipEpoch,
            RepairSourceEvidenceKind::PayloadDigest,
            RepairSourceEvidenceKind::PlacementReceipt,
        ])
    }

    fn context() -> RepairSourceVerificationContext {
        RepairSourceVerificationContext::new(EpochId::new(8), 100, [MemberId::new(7)])
    }

    fn accepted_manifest() -> RepairSourceReceiptManifest {
        RepairSourceReceiptManifest {
            source_node_id: MemberId::new(7),
            dataset_id: RepairDatasetId::new(42),
            subject: RepairSourceSubject::object(9001),
            evidence_digest: Some(digest(1)),
            freshness: RepairSourceFreshness::new(EpochId::new(8), 13, 144, EpochId::new(8)),
            decision: RepairSourceDecision::Accepted,
            validation_tier: RepairSourceValidationTier::ModelSourceEvidence,
            required_evidence: required_evidence(),
            provided_evidence: provided_evidence(),
            decision_reason_refs: BTreeSet::from(["issue-548:model-source-only".to_string()]),
            related_claim_refs: BTreeSet::from([
                "family.replication_model.repair_source_receipts".to_string()
            ]),
            related_issue_refs: BTreeSet::from([548]),
        }
    }

    #[test]
    fn accepts_source_with_required_evidence() {
        let manifest = accepted_manifest();
        let verified = manifest.verify(&context()).expect("accepted source");

        assert_eq!(verified.source_node_id, MemberId::new(7));
        assert_eq!(verified.dataset_id, RepairDatasetId::new(42));
        assert_eq!(verified.subject, RepairSourceSubject::object(9001));
        assert_eq!(verified.decision, RepairSourceDecision::Accepted);
    }

    #[test]
    fn rejects_stale_source_receipt() {
        let mut manifest = accepted_manifest();
        manifest.freshness.observed_freshness_frontier = 99;

        let err = manifest.verify(&context()).expect_err("stale source");

        assert_eq!(
            err,
            RepairSourceVerificationError::StaleReceipt {
                min_freshness_frontier: 100,
                observed_freshness_frontier: 99,
                valid_until_epoch: EpochId::new(8),
                expected_membership_epoch: EpochId::new(8),
            }
        );
    }

    #[test]
    fn rejects_mismatched_epoch() {
        let mut manifest = accepted_manifest();
        manifest.freshness.membership_epoch = EpochId::new(9);

        let err = manifest.verify(&context()).expect_err("mismatched epoch");

        assert_eq!(
            err,
            RepairSourceVerificationError::MismatchedEpoch {
                expected: EpochId::new(8),
                actual: EpochId::new(9),
            }
        );
    }

    #[test]
    fn rejects_missing_digest() {
        let mut manifest = accepted_manifest();
        manifest.evidence_digest = None;

        let err = manifest.verify(&context()).expect_err("missing digest");

        assert_eq!(err, RepairSourceVerificationError::MissingEvidenceDigest);
    }

    #[test]
    fn rejects_unknown_source_id() {
        let mut manifest = accepted_manifest();
        manifest.source_node_id = MemberId::new(77);

        let err = manifest.verify(&context()).expect_err("unknown source");

        assert_eq!(
            err,
            RepairSourceVerificationError::UnknownSourceId {
                source_node_id: MemberId::new(77),
            }
        );
    }

    #[test]
    fn rejects_accepted_decision_without_required_evidence() {
        let mut manifest = accepted_manifest();
        manifest.required_evidence.clear();

        let err = manifest
            .verify(&context())
            .expect_err("accepted without required evidence");

        assert_eq!(
            err,
            RepairSourceVerificationError::AcceptedWithoutRequiredEvidence
        );
    }

    #[test]
    fn rejects_accepted_decision_missing_required_evidence() {
        let mut manifest = accepted_manifest();
        manifest
            .provided_evidence
            .remove(&RepairSourceEvidenceKind::PayloadDigest);

        let err = manifest
            .verify(&context())
            .expect_err("missing required evidence");

        assert_eq!(
            err,
            RepairSourceVerificationError::MissingRequiredEvidence {
                missing: vec![RepairSourceEvidenceKind::PayloadDigest],
            }
        );
    }

    #[test]
    fn serializes_deterministically() {
        let manifest = accepted_manifest();
        let json = serde_json::to_string(&manifest).expect("serialize");
        let digest_json = std::iter::repeat("1")
            .take(32)
            .collect::<Vec<_>>()
            .join(",");
        let expected = format!(
            "{{\"source_node_id\":7,\"dataset_id\":42,\"subject\":{{\"Object\":{{\"object_id\":9001}}}},\"evidence_digest\":[{digest_json}],\"freshness\":{{\"membership_epoch\":8,\"source_epoch\":13,\"observed_freshness_frontier\":144,\"valid_until_epoch\":8}},\"decision\":\"Accepted\",\"validation_tier\":\"ModelSourceEvidence\",\"required_evidence\":[\"FreshnessFence\",\"MembershipEpoch\",\"PayloadDigest\"],\"provided_evidence\":[\"FreshnessFence\",\"MembershipEpoch\",\"PayloadDigest\",\"PlacementReceipt\"],\"decision_reason_refs\":[\"issue-548:model-source-only\"],\"related_claim_refs\":[\"family.replication_model.repair_source_receipts\"],\"related_issue_refs\":[548]}}"
        );

        assert_eq!(json, expected);

        let round_trip: RepairSourceReceiptManifest =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(round_trip, manifest);
        assert_eq!(
            serde_json::to_string(&round_trip).expect("serialize again"),
            json
        );
    }
}
