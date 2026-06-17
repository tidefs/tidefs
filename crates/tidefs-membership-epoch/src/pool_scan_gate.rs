//! Pool-scan evidence gate for membership epoch promotion.
//!
//! This module binds epoch promotion to a committed pool scan. Promotion only
//! builds a quorum proposal from members whose current label fingerprint agrees
//! with the committed pool-scan evidence for the same epoch transition.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

use tidefs_types_pool_label_core::PoolLabelFingerprint;

use crate::{quorum, MembershipEpoch};

const SCAN_EVIDENCE_DOMAIN: &[u8] = b"tidefs-membership-epoch-pool-scan-evidence-v1";

/// Label-agreement evidence for one candidate epoch member.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochMemberLabelFingerprint {
    /// Member identity in the membership epoch.
    pub member_id: u64,
    /// Committed label-agreement fingerprint for this member.
    pub label_fingerprint: PoolLabelFingerprint,
}

impl EpochMemberLabelFingerprint {
    /// Create a member/fingerprint pair.
    #[must_use]
    pub const fn new(member_id: u64, label_fingerprint: PoolLabelFingerprint) -> Self {
        Self {
            member_id,
            label_fingerprint,
        }
    }
}

/// Committed or pending pool-scan evidence bound to one epoch promotion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PoolScanEvidence {
    /// Epoch the promotion advances from.
    pub prior_epoch_id: u64,
    /// Epoch the promotion advances to.
    pub proposed_epoch_id: u64,
    /// True only after the scan evidence and committed-root observation are durable.
    pub committed: bool,
    /// Committed transaction group that made this scan durable, if known.
    pub committed_txg: Option<u64>,
    /// Number of member identities the scan must confirm before promotion.
    pub expected_member_count: usize,
    /// Sorted, deduplicated committed member-label evidence.
    pub members: Vec<EpochMemberLabelFingerprint>,
    /// BLAKE3-256 digest over the epoch binding and member evidence.
    pub scan_fingerprint: [u8; 32],
}

impl PoolScanEvidence {
    /// Create committed pool-scan evidence.
    #[must_use]
    pub fn committed(
        prior_epoch_id: u64,
        proposed_epoch_id: u64,
        committed_txg: u64,
        expected_member_count: usize,
        members: impl IntoIterator<Item = EpochMemberLabelFingerprint>,
    ) -> Self {
        Self::new(
            prior_epoch_id,
            proposed_epoch_id,
            true,
            Some(committed_txg),
            expected_member_count,
            members,
        )
    }

    /// Create pending pool-scan evidence that is not yet durable.
    #[must_use]
    pub fn pending(
        prior_epoch_id: u64,
        proposed_epoch_id: u64,
        expected_member_count: usize,
        members: impl IntoIterator<Item = EpochMemberLabelFingerprint>,
    ) -> Self {
        Self::new(
            prior_epoch_id,
            proposed_epoch_id,
            false,
            None,
            expected_member_count,
            members,
        )
    }

    /// Create pool-scan evidence with an explicit commit state.
    #[must_use]
    pub fn new(
        prior_epoch_id: u64,
        proposed_epoch_id: u64,
        committed: bool,
        committed_txg: Option<u64>,
        expected_member_count: usize,
        members: impl IntoIterator<Item = EpochMemberLabelFingerprint>,
    ) -> Self {
        let members = normalize_member_fingerprints(members);
        let scan_fingerprint = compute_scan_fingerprint(
            prior_epoch_id,
            proposed_epoch_id,
            committed,
            committed_txg,
            expected_member_count,
            &members,
        );
        Self {
            prior_epoch_id,
            proposed_epoch_id,
            committed,
            committed_txg,
            expected_member_count,
            members,
            scan_fingerprint,
        }
    }

    /// Number of member identities confirmed by the scan.
    #[must_use]
    pub fn observed_member_count(&self) -> usize {
        self.members.len()
    }

    /// Return the committed label fingerprint for `member_id`, if scanned.
    #[must_use]
    pub fn label_fingerprint_for(&self, member_id: u64) -> Option<PoolLabelFingerprint> {
        self.members
            .iter()
            .find(|entry| entry.member_id == member_id)
            .map(|entry| entry.label_fingerprint)
    }
}

/// Member excluded from a promotion because its current label disagreed with
/// the committed pool scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExcludedEpochMember {
    /// Member identity excluded from the new epoch.
    pub member_id: u64,
    /// Fingerprint from committed pool-scan evidence.
    pub committed_fingerprint: PoolLabelFingerprint,
    /// Fingerprint offered by the candidate label.
    pub candidate_fingerprint: PoolLabelFingerprint,
}

/// Record of a gated epoch promotion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochPromotionRecord {
    /// Epoch the promotion advanced from.
    pub prior_epoch_id: u64,
    /// Epoch the promotion advanced to.
    pub epoch_id: u64,
    /// Monotonic proposal sequence number.
    pub sequence_number: u64,
    /// Committed transaction group that made the scan durable, if known.
    pub committed_txg: Option<u64>,
    /// Fingerprint of the committed pool-scan evidence.
    pub pool_scan_fingerprint: [u8; 32],
    /// Included members with committed label-agreement fingerprints.
    pub members: Vec<EpochMemberLabelFingerprint>,
    /// Candidate members excluded by label disagreement.
    pub excluded_members: Vec<ExcludedEpochMember>,
}

/// A proposal and its committed scan-backed epoch record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GatedEpochPromotion {
    /// Quorum proposal built from the included members.
    pub proposal: quorum::EpochProposal,
    /// Evidence record for the proposed epoch.
    pub record: EpochPromotionRecord,
}

/// Errors returned by the pool-scan promotion gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EpochPromotionGateError {
    /// Scan evidence has not been committed durably.
    PoolScanNotCommitted {
        /// Evidence prior epoch.
        prior_epoch_id: u64,
        /// Evidence target epoch.
        proposed_epoch_id: u64,
    },
    /// Scan evidence is bound to a different epoch transition.
    PoolScanEpochMismatch {
        /// Expected prior epoch.
        expected_prior_epoch_id: u64,
        /// Expected target epoch.
        expected_proposed_epoch_id: u64,
        /// Evidence prior epoch.
        evidence_prior_epoch_id: u64,
        /// Evidence target epoch.
        evidence_proposed_epoch_id: u64,
    },
    /// The committed scan has not confirmed every required member identity.
    PoolScanIncomplete {
        /// Required member count.
        expected: usize,
        /// Observed member count.
        observed: usize,
    },
    /// A candidate member has no committed scan evidence yet.
    MissingMemberEvidence {
        /// Candidate member identity.
        member_id: u64,
    },
    /// No member remains after applying scan and label-agreement gates.
    EmptyMemberSet,
    /// Existing quorum proposal validation rejected the promotion.
    Quorum(quorum::QuorumError),
}

impl fmt::Display for EpochPromotionGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PoolScanNotCommitted {
                prior_epoch_id,
                proposed_epoch_id,
            } => write!(
                f,
                "pool scan for epoch {prior_epoch_id}->{proposed_epoch_id} is not committed"
            ),
            Self::PoolScanEpochMismatch {
                expected_prior_epoch_id,
                expected_proposed_epoch_id,
                evidence_prior_epoch_id,
                evidence_proposed_epoch_id,
            } => write!(
                f,
                "pool scan evidence is bound to epoch {evidence_prior_epoch_id}->{evidence_proposed_epoch_id}, expected {expected_prior_epoch_id}->{expected_proposed_epoch_id}"
            ),
            Self::PoolScanIncomplete { expected, observed } => write!(
                f,
                "pool scan evidence incomplete: observed {observed} of {expected} member identities"
            ),
            Self::MissingMemberEvidence { member_id } => {
                write!(f, "pool scan has no committed evidence for member {member_id}")
            }
            Self::EmptyMemberSet => write!(f, "no members remain after pool-scan gate"),
            Self::Quorum(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for EpochPromotionGateError {}

impl From<quorum::QuorumError> for EpochPromotionGateError {
    fn from(value: quorum::QuorumError) -> Self {
        Self::Quorum(value)
    }
}

impl MembershipEpoch {
    /// Build a quorum proposal only after committed pool-scan and label agreement.
    ///
    /// Candidate members whose label fingerprints disagree with the committed
    /// scan are excluded from the returned proposal and recorded in
    /// [`EpochPromotionRecord::excluded_members`]. Missing or uncommitted scan
    /// evidence returns an error so callers can wait instead of advancing.
    pub fn promote_with_committed_pool_scan(
        &self,
        proposer_id: u64,
        sequence_number: u64,
        candidate_labels: &[EpochMemberLabelFingerprint],
        scan: &PoolScanEvidence,
    ) -> Result<GatedEpochPromotion, EpochPromotionGateError> {
        if !scan.committed {
            return Err(EpochPromotionGateError::PoolScanNotCommitted {
                prior_epoch_id: scan.prior_epoch_id,
                proposed_epoch_id: scan.proposed_epoch_id,
            });
        }

        let expected_proposed_epoch_id = self.epoch_id + 1;
        if scan.prior_epoch_id != self.epoch_id
            || scan.proposed_epoch_id != expected_proposed_epoch_id
        {
            return Err(EpochPromotionGateError::PoolScanEpochMismatch {
                expected_prior_epoch_id: self.epoch_id,
                expected_proposed_epoch_id,
                evidence_prior_epoch_id: scan.prior_epoch_id,
                evidence_proposed_epoch_id: scan.proposed_epoch_id,
            });
        }

        let observed = scan.observed_member_count();
        if observed < scan.expected_member_count {
            return Err(EpochPromotionGateError::PoolScanIncomplete {
                expected: scan.expected_member_count,
                observed,
            });
        }

        let candidates = normalize_member_fingerprints(candidate_labels.iter().copied());
        if candidates.is_empty() {
            return Err(EpochPromotionGateError::EmptyMemberSet);
        }

        let mut included = Vec::new();
        let mut included_ids = Vec::new();
        let mut excluded_members = Vec::new();

        for candidate in candidates {
            let Some(committed_fingerprint) = scan.label_fingerprint_for(candidate.member_id)
            else {
                return Err(EpochPromotionGateError::MissingMemberEvidence {
                    member_id: candidate.member_id,
                });
            };

            if committed_fingerprint == candidate.label_fingerprint {
                included_ids.push(candidate.member_id);
                included.push(EpochMemberLabelFingerprint::new(
                    candidate.member_id,
                    committed_fingerprint,
                ));
            } else {
                excluded_members.push(ExcludedEpochMember {
                    member_id: candidate.member_id,
                    committed_fingerprint,
                    candidate_fingerprint: candidate.label_fingerprint,
                });
            }
        }

        if included_ids.is_empty() {
            return Err(EpochPromotionGateError::EmptyMemberSet);
        }

        let proposal = self.propose(proposer_id, sequence_number, &included_ids)?;
        let record = EpochPromotionRecord {
            prior_epoch_id: self.epoch_id,
            epoch_id: proposal.proposed_epoch_id,
            sequence_number,
            committed_txg: scan.committed_txg,
            pool_scan_fingerprint: scan.scan_fingerprint,
            members: included,
            excluded_members,
        };

        Ok(GatedEpochPromotion { proposal, record })
    }
}

fn normalize_member_fingerprints(
    members: impl IntoIterator<Item = EpochMemberLabelFingerprint>,
) -> Vec<EpochMemberLabelFingerprint> {
    let by_member: BTreeMap<u64, PoolLabelFingerprint> = members
        .into_iter()
        .map(|entry| (entry.member_id, entry.label_fingerprint))
        .collect();
    by_member
        .into_iter()
        .map(|(member_id, label_fingerprint)| {
            EpochMemberLabelFingerprint::new(member_id, label_fingerprint)
        })
        .collect()
}

fn compute_scan_fingerprint(
    prior_epoch_id: u64,
    proposed_epoch_id: u64,
    committed: bool,
    committed_txg: Option<u64>,
    expected_member_count: usize,
    members: &[EpochMemberLabelFingerprint],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(SCAN_EVIDENCE_DOMAIN);
    hasher.update(&prior_epoch_id.to_le_bytes());
    hasher.update(&proposed_epoch_id.to_le_bytes());
    hasher.update(&[u8::from(committed)]);
    hasher.update(&committed_txg.unwrap_or(0).to_le_bytes());
    hasher.update(&(expected_member_count as u64).to_le_bytes());
    hasher.update(b"|members|");
    for member in members {
        hasher.update(&member.member_id.to_le_bytes());
        hasher.update(member.label_fingerprint.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EpochMemberSet, NodeIdentity};

    fn fingerprint(byte: u8) -> PoolLabelFingerprint {
        PoolLabelFingerprint([byte; 32])
    }

    fn member(member_id: u64, byte: u8) -> EpochMemberLabelFingerprint {
        EpochMemberLabelFingerprint::new(member_id, fingerprint(byte))
    }

    fn epoch(epoch_id: u64) -> MembershipEpoch {
        MembershipEpoch {
            epoch_id,
            members: EpochMemberSet::new([NodeIdentity::new(1), NodeIdentity::new(2)]),
        }
    }

    fn committed_scan(members: Vec<EpochMemberLabelFingerprint>) -> PoolScanEvidence {
        PoolScanEvidence::committed(4, 5, 99, members.len(), members)
    }

    #[test]
    fn epoch_promotion_after_committed_pool_scan() {
        let epoch = epoch(4);
        let scan = committed_scan(vec![member(1, 1), member(2, 2), member(3, 3)]);

        let promoted = epoch
            .promote_with_committed_pool_scan(
                1,
                5,
                &[member(3, 3), member(1, 1), member(2, 2)],
                &scan,
            )
            .unwrap();

        assert_eq!(promoted.proposal.prior_epoch_id, 4);
        assert_eq!(promoted.proposal.proposed_epoch_id, 5);
        assert_eq!(promoted.proposal.proposed_members, vec![1, 2, 3]);
        assert_eq!(
            promoted
                .record
                .members
                .iter()
                .map(|entry| entry.member_id)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn label_disagreement_rejects_member_from_new_epoch() {
        let epoch = epoch(4);
        let scan = committed_scan(vec![member(1, 1), member(2, 2), member(3, 3)]);

        let promoted = epoch
            .promote_with_committed_pool_scan(
                1,
                5,
                &[member(1, 1), member(2, 2), member(3, 9)],
                &scan,
            )
            .unwrap();

        assert_eq!(promoted.proposal.proposed_members, vec![1, 2]);
        assert_eq!(promoted.record.excluded_members.len(), 1);
        assert_eq!(promoted.record.excluded_members[0].member_id, 3);
        assert_eq!(
            promoted.record.excluded_members[0].committed_fingerprint,
            fingerprint(3)
        );
        assert_eq!(
            promoted.record.excluded_members[0].candidate_fingerprint,
            fingerprint(9)
        );
    }

    #[test]
    fn partial_pool_scan_must_wait() {
        let epoch = epoch(4);
        let scan = PoolScanEvidence::committed(4, 5, 99, 3, [member(1, 1), member(2, 2)]);

        let err = epoch
            .promote_with_committed_pool_scan(1, 5, &[member(1, 1), member(2, 2)], &scan)
            .unwrap_err();

        assert!(matches!(
            err,
            EpochPromotionGateError::PoolScanIncomplete {
                expected: 3,
                observed: 2,
            }
        ));
    }

    #[test]
    fn uncommitted_pool_scan_must_wait() {
        let epoch = epoch(4);
        let scan = PoolScanEvidence::pending(4, 5, 2, [member(1, 1), member(2, 2)]);

        let err = epoch
            .promote_with_committed_pool_scan(1, 5, &[member(1, 1), member(2, 2)], &scan)
            .unwrap_err();

        assert!(matches!(
            err,
            EpochPromotionGateError::PoolScanNotCommitted {
                prior_epoch_id: 4,
                proposed_epoch_id: 5,
            }
        ));
    }

    #[test]
    fn epoch_record_includes_committed_label_fingerprints() {
        let epoch = epoch(4);
        let scan = committed_scan(vec![member(1, 1), member(2, 2)]);

        let promoted = epoch
            .promote_with_committed_pool_scan(1, 5, &[member(1, 1), member(2, 2)], &scan)
            .unwrap();

        assert_eq!(promoted.record.committed_txg, Some(99));
        assert_eq!(promoted.record.pool_scan_fingerprint, scan.scan_fingerprint);
        assert_eq!(
            promoted.record.members,
            vec![
                EpochMemberLabelFingerprint::new(1, fingerprint(1)),
                EpochMemberLabelFingerprint::new(2, fingerprint(2)),
            ]
        );
    }
}
