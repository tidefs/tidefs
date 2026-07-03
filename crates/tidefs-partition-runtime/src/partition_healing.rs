// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! PartitionHealingProtocol: c2 joint config creation, receipt frontier
//! exchange, divergence classification, and reconciliation strategy selection.

use crate::types::{
    now_millis, DivergenceClass, HealingFrontierError, PartitionHazardClass, ReceiptFrontier,
    ReconciliationEvidence, ReconciliationEvidenceError, ReconciliationStrategy,
};
use std::collections::BTreeSet;
use tidefs_membership_epoch::{EpochId, MemberId};

// ---------------------------------------------------------------------------
// PartitionHealingProtocol
// ---------------------------------------------------------------------------

/// Drives the partition healing protocol after connectivity is restored.
///
/// Phases:
/// 1. Receipt frontier exchange between quorum side and minority side
/// 2. Divergence classification (conflicts, divergent, none)
/// 3. Reconciliation strategy selection (full catch-up, scoped, escalation)
/// 4. Minority members rejoin as Learners in a c2 joint config
/// 5. Catch-up and promotion to Voters
pub struct PartitionHealingProtocol {
    /// My member ID.
    pub my_id: MemberId,
    /// The joint config epoch during healing.
    pub joint_epoch: Option<EpochId>,
    /// Receipt frontier from the quorum side.
    pub quorum_frontier: Option<ReceiptFrontier>,
    /// Receipt frontier from this (minority) side.
    pub minority_frontier: Option<ReceiptFrontier>,
    /// Divergence classification result.
    pub divergence: Option<DivergenceClass>,
    /// Selected reconciliation strategy.
    pub strategy: Option<ReconciliationStrategy>,
    /// Members that are rejoining as Learners.
    pub rejoining_members: Vec<MemberId>,
    /// Members that have completed catch-up.
    pub caught_up_members: Vec<MemberId>,
    /// Whether healing is in progress.
    pub healing_in_progress: bool,
    /// Whether healing is complete.
    pub healing_complete: bool,
}

const MAX_FRONTIER_AGE_MILLIS: u64 = 30_000;

impl PartitionHealingProtocol {
    /// Create a new healing protocol instance.
    pub fn new(my_id: MemberId) -> Self {
        Self {
            my_id,
            joint_epoch: None,
            quorum_frontier: None,
            minority_frontier: None,
            divergence: None,
            strategy: None,
            rejoining_members: Vec::new(),
            caught_up_members: Vec::new(),
            healing_in_progress: false,
            healing_complete: false,
        }
    }

    /// Begin the healing protocol: create a c2 joint config epoch.
    pub fn begin_healing(
        &mut self,
        current_epoch: EpochId,
        rejoining_members: Vec<MemberId>,
    ) -> EpochId {
        let joint_epoch = current_epoch.next();
        self.joint_epoch = Some(joint_epoch);
        self.rejoining_members = rejoining_members;
        self.healing_in_progress = true;
        self.healing_complete = false;
        self.divergence = None;
        self.strategy = None;
        self.quorum_frontier = None;
        self.minority_frontier = None;
        self.caught_up_members.clear();
        joint_epoch
    }

    /// Exchange receipt frontiers: quorum side provides its frontier,
    /// minority side provides its frontier.
    pub fn exchange_frontiers(
        &mut self,
        quorum_frontier: ReceiptFrontier,
        minority_frontier: ReceiptFrontier,
    ) -> Result<(), HealingFrontierError> {
        self.validate_frontiers(&quorum_frontier, &minority_frontier)?;
        self.quorum_frontier = Some(quorum_frontier);
        self.minority_frontier = Some(minority_frontier);
        Ok(())
    }

    fn validate_frontiers(
        &self,
        quorum_frontier: &ReceiptFrontier,
        minority_frontier: &ReceiptFrontier,
    ) -> Result<(), HealingFrontierError> {
        if !self.healing_in_progress {
            return Err(HealingFrontierError::HealingNotInProgress);
        }

        let joint_epoch = self
            .joint_epoch
            .ok_or(HealingFrontierError::HealingNotInProgress)?;
        validate_frontier_shape(
            quorum_frontier,
            PartitionHazardClass::QuorumSide,
            joint_epoch,
        )?;
        validate_frontier_shape(
            minority_frontier,
            PartitionHazardClass::MinoritySide,
            joint_epoch,
        )?;

        let expected: BTreeSet<MemberId> = self.rejoining_members.iter().copied().collect();
        let actual: BTreeSet<MemberId> = minority_frontier.members.iter().copied().collect();
        if expected != actual {
            return Err(HealingFrontierError::UnexpectedMinorityMembers {
                expected: expected.into_iter().collect(),
                actual: actual.into_iter().collect(),
            });
        }

        Ok(())
    }

    /// Classify the divergence between the two frontiers.
    ///
    /// Compares receipt IDs known to each side to determine if there
    /// are conflicts, simple divergence, or no divergence.
    pub fn classify_divergence(&mut self) -> Result<DivergenceClass, HealingFrontierError> {
        let quorum = match &self.quorum_frontier {
            Some(f) => f.receipt_ids.clone(),
            None => return Err(HealingFrontierError::MissingQuorumFrontier),
        };
        let minority = match &self.minority_frontier {
            Some(f) => f.receipt_ids.clone(),
            None => return Err(HealingFrontierError::MissingQuorumFrontier),
        };

        let quorum_set: BTreeSet<u64> = quorum.iter().copied().collect();
        let minority_set: BTreeSet<u64> = minority.iter().copied().collect();

        let minority_only: Vec<u64> = minority_set.difference(&quorum_set).copied().collect();
        let quorum_only: Vec<u64> = quorum_set.difference(&minority_set).copied().collect();

        // If minority has receipts not on quorum side, those are conflicts
        if !minority_only.is_empty() {
            // These receipts were minted on the minority side during the
            // partition — the quorum side doesn't know about them.
            // They conflict with whatever the quorum side minted.
            let result = DivergenceClass::Conflicts {
                conflicting_receipts: minority_only.clone(),
                conflict_count: minority_only.len(),
            };
            self.divergence = Some(result.clone());
            return Ok(result);
        }

        // If quorum side has receipts the minority doesn't: simple catch-up
        if !quorum_only.is_empty() {
            let result = DivergenceClass::Divergent {
                minority_receipt_count: minority.len(),
                quorum_side_receipt_count: quorum.len(),
            };
            self.divergence = Some(result.clone());
            return Ok(result);
        }

        let result = DivergenceClass::None;
        self.divergence = Some(result.clone());
        Ok(result)
    }

    /// Select a reconciliation strategy based on divergence classification.
    pub fn select_strategy(
        &mut self,
        divergence: &DivergenceClass,
        missed_epochs: Vec<EpochId>,
    ) -> ReconciliationStrategy {
        let strategy = match divergence {
            DivergenceClass::None => ReconciliationStrategy::NoneNeeded,
            DivergenceClass::Conflicts {
                conflicting_receipts,
                ..
            } => {
                if conflicting_receipts.is_empty() {
                    ReconciliationStrategy::Scoped {
                        receipts_to_ship: Vec::new(),
                        receipts_to_rollback: Vec::new(),
                    }
                } else {
                    // Minority-side writes must be rolled back; quorum side wins
                    ReconciliationStrategy::Scoped {
                        receipts_to_ship: Vec::new(),
                        receipts_to_rollback: conflicting_receipts.clone(),
                    }
                }
            }
            DivergenceClass::Divergent {
                minority_receipt_count: _,
                quorum_side_receipt_count,
            } => {
                let quorum_only: Vec<u64> = self
                    .quorum_frontier
                    .as_ref()
                    .map(|f| {
                        let minority_ids: BTreeSet<u64> = self
                            .minority_frontier
                            .as_ref()
                            .map(|m| m.receipt_ids.iter().copied().collect())
                            .unwrap_or_default();
                        f.receipt_ids
                            .iter()
                            .copied()
                            .filter(|id| !minority_ids.contains(id))
                            .collect()
                    })
                    .unwrap_or_default();

                if quorum_only.len() <= 100 && missed_epochs.len() <= 3 {
                    ReconciliationStrategy::Scoped {
                        receipts_to_ship: quorum_only,
                        receipts_to_rollback: Vec::new(),
                    }
                } else {
                    ReconciliationStrategy::FullCatchup {
                        missed_epochs: missed_epochs.clone(),
                        estimated_receipts: *quorum_side_receipt_count,
                    }
                }
            }
        };

        self.strategy = Some(strategy.clone());
        strategy
    }

    /// Determine whether the rejoining member is a Witness-only member.
    /// Witness-only members need no data reconciliation — just rejoin epoch.
    #[must_use]
    pub fn is_witness_only_rejoin(&self) -> bool {
        // If the minority side has no receipts, it may be a witness-only member
        self.minority_frontier
            .as_ref()
            .map(|f| f.receipt_ids.is_empty())
            .unwrap_or(false)
    }

    /// Mark a rejoining member as caught up.
    pub fn mark_caught_up(
        &mut self,
        member_id: MemberId,
        evidence: ReconciliationEvidence,
    ) -> Result<(), ReconciliationEvidenceError> {
        if !self.healing_in_progress {
            return Err(ReconciliationEvidenceError::HealingNotInProgress);
        }
        if !self.rejoining_members.contains(&member_id) {
            return Err(ReconciliationEvidenceError::UnknownRejoiningMember(
                member_id,
            ));
        }
        self.validate_reconciliation_evidence(&evidence)?;
        if !self.caught_up_members.contains(&member_id) {
            self.caught_up_members.push(member_id);
        }
        Ok(())
    }

    fn validate_reconciliation_evidence(
        &self,
        evidence: &ReconciliationEvidence,
    ) -> Result<(), ReconciliationEvidenceError> {
        let strategy = self
            .strategy
            .as_ref()
            .ok_or(ReconciliationEvidenceError::MissingStrategy)?;
        match (strategy, evidence) {
            (
                ReconciliationStrategy::NoneNeeded,
                ReconciliationEvidence::NoneNeeded { frontier_epoch, .. },
            ) => {
                let expected_epoch = self
                    .joint_epoch
                    .or_else(|| self.quorum_frontier.as_ref().map(|f| f.frontier_epoch));
                if expected_epoch == Some(*frontier_epoch) {
                    Ok(())
                } else {
                    Err(ReconciliationEvidenceError::EvidenceDoesNotMatchStrategy)
                }
            }
            (
                ReconciliationStrategy::Scoped {
                    receipts_to_ship,
                    receipts_to_rollback,
                },
                ReconciliationEvidence::Scoped {
                    shipped_receipts,
                    rolled_back_receipts,
                    ..
                },
            ) => {
                ensure_contains_all(shipped_receipts, receipts_to_ship).map_err(|missing| {
                    ReconciliationEvidenceError::MissingRequiredReceiptShipment {
                        missing_receipts: missing,
                    }
                })?;
                ensure_contains_all(rolled_back_receipts, receipts_to_rollback).map_err(
                    |missing| ReconciliationEvidenceError::MissingRequiredRollback {
                        missing_receipts: missing,
                    },
                )?;
                Ok(())
            }
            (
                ReconciliationStrategy::FullCatchup {
                    missed_epochs,
                    estimated_receipts,
                },
                ReconciliationEvidence::FullCatchup {
                    replayed_epochs,
                    replayed_receipt_count,
                    ..
                },
            ) => {
                let replayed: BTreeSet<EpochId> = replayed_epochs.iter().copied().collect();
                let missing_epochs: Vec<EpochId> = missed_epochs
                    .iter()
                    .copied()
                    .filter(|epoch| !replayed.contains(epoch))
                    .collect();
                if !missing_epochs.is_empty() {
                    return Err(ReconciliationEvidenceError::MissingRequiredEpochReplay {
                        missing_epochs,
                    });
                }
                if *replayed_receipt_count < *estimated_receipts {
                    return Err(ReconciliationEvidenceError::InsufficientReceiptReplay {
                        expected_at_least: *estimated_receipts,
                        actual: *replayed_receipt_count,
                    });
                }
                Ok(())
            }
            (
                ReconciliationStrategy::OperatorEscalation { reason },
                ReconciliationEvidence::OperatorEscalation {
                    reason: evidence_reason,
                    ..
                },
            ) if reason == evidence_reason => Ok(()),
            _ => Err(ReconciliationEvidenceError::EvidenceDoesNotMatchStrategy),
        }
    }

    /// Check if all rejoining members are caught up.
    #[must_use]
    pub fn all_caught_up(&self) -> bool {
        self.rejoining_members
            .iter()
            .all(|m| self.caught_up_members.contains(m))
    }

    /// Complete the healing protocol.
    pub fn complete_healing(&mut self) {
        self.healing_in_progress = false;
        self.healing_complete = true;
    }

    /// Compute the missed epochs between the two frontiers.
    #[must_use]
    pub fn compute_missed_epochs(&self) -> Vec<EpochId> {
        let q_epoch = self
            .quorum_frontier
            .as_ref()
            .map(|f| f.frontier_epoch)
            .unwrap_or(EpochId::ZERO);
        let m_epoch = self
            .minority_frontier
            .as_ref()
            .map(|f| f.frontier_epoch)
            .unwrap_or(EpochId::ZERO);

        if q_epoch.0 <= m_epoch.0 {
            return Vec::new();
        }

        ((m_epoch.0 + 1)..=q_epoch.0).map(EpochId::new).collect()
    }

    /// Reset the healing protocol for a fresh start.
    pub fn reset(&mut self) {
        self.joint_epoch = None;
        self.quorum_frontier = None;
        self.minority_frontier = None;
        self.divergence = None;
        self.strategy = None;
        self.rejoining_members.clear();
        self.caught_up_members.clear();
        self.healing_in_progress = false;
        self.healing_complete = false;
    }
}

fn validate_frontier_shape(
    frontier: &ReceiptFrontier,
    expected_side: PartitionHazardClass,
    expected_epoch: EpochId,
) -> Result<(), HealingFrontierError> {
    if frontier.side != expected_side {
        return Err(HealingFrontierError::WrongFrontierSide {
            expected: expected_side,
            actual: frontier.side,
        });
    }
    if frontier.frontier_epoch != expected_epoch {
        return Err(HealingFrontierError::FrontierEpochMismatch {
            expected: expected_epoch,
            actual: frontier.frontier_epoch,
        });
    }
    if frontier.members.is_empty() {
        return Err(HealingFrontierError::EmptyFrontierMembers);
    }
    if let Some(invalid) = frontier.receipt_ids.iter().copied().find(|id| *id == 0) {
        return Err(HealingFrontierError::InvalidReceiptId(invalid));
    }

    let now = now_millis();
    let age = now.saturating_sub(frontier.frontier_millis);
    if age > MAX_FRONTIER_AGE_MILLIS {
        return Err(HealingFrontierError::StaleFrontier {
            frontier_millis: frontier.frontier_millis,
            now_millis: now,
            max_age_millis: MAX_FRONTIER_AGE_MILLIS,
        });
    }

    Ok(())
}

fn ensure_contains_all(actual: &[u64], required: &[u64]) -> Result<(), Vec<u64>> {
    let actual: BTreeSet<u64> = actual.iter().copied().collect();
    let missing: Vec<u64> = required
        .iter()
        .copied()
        .filter(|receipt| !actual.contains(receipt))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PartitionHazardClass;

    fn front(side: PartitionHazardClass, receipt_ids: Vec<u64>, epoch: u64) -> ReceiptFrontier {
        let members = match side {
            PartitionHazardClass::QuorumSide => vec![MemberId::new(1)],
            PartitionHazardClass::MinoritySide => vec![MemberId::new(2)],
            PartitionHazardClass::PartitionAmbiguous => vec![MemberId::new(3)],
        };
        ReceiptFrontier {
            side,
            members,
            receipt_ids,
            frontier_epoch: EpochId::new(epoch),
            frontier_millis: crate::types::now_millis(),
        }
    }

    fn healing_proto_for_epoch(epoch: u64) -> PartitionHealingProtocol {
        let mut proto = PartitionHealingProtocol::new(MemberId::new(1));
        proto.begin_healing(EpochId::new(epoch - 1), vec![MemberId::new(2)]);
        proto
    }

    #[test]
    fn test_no_divergence_when_identical() {
        let mut proto = healing_proto_for_epoch(5);
        proto
            .exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2, 3], 5),
                front(PartitionHazardClass::MinoritySide, vec![1, 2, 3], 5),
            )
            .unwrap();
        let div = proto.classify_divergence().unwrap();
        assert!(matches!(div, DivergenceClass::None));
    }

    #[test]
    fn test_divergence_when_quorum_has_more() {
        let mut proto = healing_proto_for_epoch(5);
        proto
            .exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2, 3, 4, 5], 5),
                front(PartitionHazardClass::MinoritySide, vec![1, 2, 3], 5),
            )
            .unwrap();
        let div = proto.classify_divergence().unwrap();
        assert!(matches!(div, DivergenceClass::Divergent { .. }));
    }

    #[test]
    fn test_conflict_when_minority_has_receipts_not_on_quorum() {
        let mut proto = healing_proto_for_epoch(5);
        proto
            .exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2, 3], 5),
                front(PartitionHazardClass::MinoritySide, vec![1, 2, 3, 10, 11], 5),
            )
            .unwrap();
        let div = proto.classify_divergence().unwrap();
        assert!(matches!(div, DivergenceClass::Conflicts { .. }));
    }

    #[test]
    fn test_missed_epochs_computation() {
        let mut proto = PartitionHealingProtocol::new(MemberId::new(1));
        proto.quorum_frontier = Some(front(PartitionHazardClass::QuorumSide, vec![1, 2], 10));
        proto.minority_frontier = Some(front(PartitionHazardClass::MinoritySide, vec![1], 7));
        let missed = proto.compute_missed_epochs();
        assert_eq!(missed.len(), 3); // epochs 8, 9, 10
    }

    #[test]
    fn test_select_full_catchup_for_large_divergence() {
        let mut proto = PartitionHealingProtocol::new(MemberId::new(1));
        let divergence = DivergenceClass::Divergent {
            minority_receipt_count: 10,
            quorum_side_receipt_count: 500,
        };
        let strategy = proto.select_strategy(
            &divergence,
            vec![
                EpochId::new(8),
                EpochId::new(9),
                EpochId::new(10),
                EpochId::new(11),
            ],
        );
        assert!(matches!(
            strategy,
            ReconciliationStrategy::FullCatchup { .. }
        ));
    }

    #[test]
    fn test_select_scoped_for_small_divergence() {
        let mut proto = healing_proto_for_epoch(2);
        proto
            .exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2, 3, 4], 2),
                front(PartitionHazardClass::MinoritySide, vec![1, 2], 2),
            )
            .unwrap();
        proto.classify_divergence().unwrap();
        let divergence = DivergenceClass::Divergent {
            minority_receipt_count: 2,
            quorum_side_receipt_count: 4,
        };
        let strategy = proto.select_strategy(&divergence, vec![EpochId::new(2)]);
        assert!(matches!(strategy, ReconciliationStrategy::Scoped { .. }));
    }

    #[test]
    fn test_witness_only_rejoin() {
        let mut proto = healing_proto_for_epoch(5);
        proto
            .exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2, 3], 5),
                front(PartitionHazardClass::MinoritySide, vec![], 5),
            )
            .unwrap();
        assert!(proto.is_witness_only_rejoin());
    }

    #[test]
    fn test_healing_lifecycle() {
        let mut proto = PartitionHealingProtocol::new(MemberId::new(1));
        assert!(!proto.healing_in_progress);

        let joint_epoch = proto.begin_healing(EpochId::new(5), vec![MemberId::new(2)]);
        assert!(proto.healing_in_progress);
        assert_eq!(joint_epoch, EpochId::new(6));
        assert_eq!(proto.rejoining_members, vec![MemberId::new(2)]);

        proto.strategy = Some(ReconciliationStrategy::NoneNeeded);
        proto
            .mark_caught_up(
                MemberId::new(2),
                ReconciliationEvidence::NoneNeeded {
                    frontier_epoch: joint_epoch,
                    verified_at_millis: now_millis(),
                },
            )
            .unwrap();
        assert!(proto.all_caught_up());

        proto.complete_healing();
        assert!(!proto.healing_in_progress);
        assert!(proto.healing_complete);
    }

    #[test]
    fn test_classify_requires_frontiers() {
        let mut proto = healing_proto_for_epoch(5);
        assert_eq!(
            proto.classify_divergence(),
            Err(HealingFrontierError::MissingQuorumFrontier)
        );
    }

    #[test]
    fn test_mismatched_minority_members_refused() {
        let mut proto = healing_proto_for_epoch(5);
        let mut minority = front(PartitionHazardClass::MinoritySide, vec![1], 5);
        minority.members = vec![MemberId::new(3)];
        assert!(matches!(
            proto.exchange_frontiers(
                front(PartitionHazardClass::QuorumSide, vec![1, 2], 5),
                minority
            ),
            Err(HealingFrontierError::UnexpectedMinorityMembers { .. })
        ));
    }

    #[test]
    fn test_caught_up_requires_strategy_matching_evidence() {
        let mut proto = healing_proto_for_epoch(5);
        proto.strategy = Some(ReconciliationStrategy::Scoped {
            receipts_to_ship: vec![4, 5],
            receipts_to_rollback: vec![9],
        });

        assert!(matches!(
            proto.mark_caught_up(
                MemberId::new(2),
                ReconciliationEvidence::Scoped {
                    shipped_receipts: vec![4],
                    rolled_back_receipts: vec![9],
                    verified_at_millis: now_millis(),
                },
            ),
            Err(ReconciliationEvidenceError::MissingRequiredReceiptShipment { .. })
        ));

        proto
            .mark_caught_up(
                MemberId::new(2),
                ReconciliationEvidence::Scoped {
                    shipped_receipts: vec![4, 5],
                    rolled_back_receipts: vec![9],
                    verified_at_millis: now_millis(),
                },
            )
            .unwrap();
        assert!(proto.all_caught_up());
    }
}
