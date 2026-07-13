// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Failed-quorum ledger validation helpers.
//!
//! This module models the validation boundary from ADR-0008. It keeps
//! per-replica failed-quorum evidence visible to claim-facing checks while
//! scrub/repair convergence remains owned by the later consumer path.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const SCRUB_REPAIR_CONSUMER_BLOCKER: u64 = 1997;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FailedQuorumScenario {
    pub scenario_id: String,
    pub mutation_id: String,
    pub quorum_size: usize,
    pub aggregate_ack_count: usize,
    pub replicas: Vec<ReplicaEvidence>,
    pub local_rollback: LocalRollbackEvidence,
    #[serde(default)]
    pub compensating_attempts: Vec<CompensatingEvidence>,
}

impl FailedQuorumScenario {
    #[must_use]
    pub fn evaluate(&self) -> FailedQuorumValidationReport {
        evaluate_failed_quorum_scenario(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ReplicaEvidence {
    pub replica_id: u64,
    pub state: ReplicaEvidenceState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum ReplicaEvidenceState {
    Acknowledged,
    Rejected { reason: String },
    SentWithoutAck { error: String },
    NoSession { error: String },
    NoSend { error: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "state", content = "detail")]
pub enum LocalRollbackEvidence {
    RestoredPreviousPayload,
    DeletedNewPayload,
    NotAttempted,
    Failed { error: String },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct CompensatingEvidence {
    pub replica_id: u64,
    pub outcome: CompensatingOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "outcome", content = "detail")]
pub enum CompensatingOutcome {
    Acknowledged,
    Rejected { reason: String },
    SentWithoutAck { error: String },
    NotSent { reason: String },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClaimSurface {
    DistributedTransactionClosure,
    RepairCompletion,
    ReleaseReadiness,
    Production,
    SuccessorComparator,
    OpenZfsCeph,
    RdmaCorrectness,
}

impl ClaimSurface {
    #[must_use]
    pub const fn all_fail_closed_surfaces() -> [Self; 7] {
        [
            Self::DistributedTransactionClosure,
            Self::RepairCompletion,
            Self::ReleaseReadiness,
            Self::Production,
            Self::SuccessorComparator,
            Self::OpenZfsCeph,
            Self::RdmaCorrectness,
        ]
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct FailedQuorumValidationReport {
    pub scenario_id: String,
    pub mutation_id: String,
    pub quorum_size: usize,
    pub aggregate_ack_count: usize,
    pub aggregate_ack_count_reaches_quorum: bool,
    pub unresolved_rows: Vec<UnresolvedEvidenceRow>,
    pub claim_refusals: Vec<ClaimRefusal>,
    pub consumer_refusal: Option<ConsumerRefusal>,
}

impl FailedQuorumValidationReport {
    #[must_use]
    pub fn has_unresolved_evidence(&self) -> bool {
        !self.unresolved_rows.is_empty()
    }

    #[must_use]
    pub fn refuses_surface(&self, surface: ClaimSurface) -> bool {
        self.claim_refusals
            .iter()
            .any(|refusal| refusal.surface == surface)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct UnresolvedEvidenceRow {
    pub replica_id: Option<u64>,
    pub evidence_kind: UnresolvedEvidenceKind,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnresolvedEvidenceKind {
    ReplicaAcknowledged,
    ReplicaRejected,
    SentWithoutAck,
    NoSession,
    NoSend,
    LocalRollbackIncomplete,
    CompensatingRejected,
    CompensatingSentWithoutAck,
    CompensatingNotSent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ClaimRefusal {
    pub surface: ClaimSurface,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct ConsumerRefusal {
    pub consumer: String,
    pub blocking_issue: u64,
    pub reason: String,
}

#[must_use]
pub fn evaluate_failed_quorum_scenario(
    scenario: &FailedQuorumScenario,
) -> FailedQuorumValidationReport {
    let mut unresolved_rows = Vec::new();

    for replica in &scenario.replicas {
        unresolved_rows.push(replica_unresolved_row(replica));
    }

    if let Some(row) = local_rollback_unresolved_row(&scenario.local_rollback) {
        unresolved_rows.push(row);
    }

    for attempt in &scenario.compensating_attempts {
        if let Some(row) = compensating_unresolved_row(attempt) {
            unresolved_rows.push(row);
        }
    }

    let claim_refusals = if unresolved_rows.is_empty() {
        Vec::new()
    } else {
        ClaimSurface::all_fail_closed_surfaces()
            .into_iter()
            .map(|surface| ClaimRefusal {
                surface,
                reason: format!(
                    "failed-quorum mutation {} still has per-replica unresolved evidence",
                    scenario.mutation_id
                ),
            })
            .collect()
    };

    let consumer_refusal = if unresolved_rows.is_empty() {
        None
    } else {
        Some(ConsumerRefusal {
            consumer: "scrub-repair failed-quorum ledger consumer".to_string(),
            blocking_issue: SCRUB_REPAIR_CONSUMER_BLOCKER,
            reason: "refuse repair completion while unresolved failed-quorum rows remain"
                .to_string(),
        })
    };

    FailedQuorumValidationReport {
        scenario_id: scenario.scenario_id.clone(),
        mutation_id: scenario.mutation_id.clone(),
        quorum_size: scenario.quorum_size,
        aggregate_ack_count: scenario.aggregate_ack_count,
        aggregate_ack_count_reaches_quorum: scenario.aggregate_ack_count >= scenario.quorum_size,
        unresolved_rows,
        claim_refusals,
        consumer_refusal,
    }
}

pub fn replay_failed_quorum_report(
    scenario: &FailedQuorumScenario,
) -> Result<FailedQuorumValidationReport, serde_json::Error> {
    let encoded = serde_json::to_string(scenario)?;
    let replayed = serde_json::from_str::<FailedQuorumScenario>(&encoded)?;
    Ok(evaluate_failed_quorum_scenario(&replayed))
}

fn replica_unresolved_row(replica: &ReplicaEvidence) -> UnresolvedEvidenceRow {
    match &replica.state {
        ReplicaEvidenceState::Acknowledged => UnresolvedEvidenceRow {
            replica_id: Some(replica.replica_id),
            evidence_kind: UnresolvedEvidenceKind::ReplicaAcknowledged,
            reason: "replica acknowledged a mutation that failed quorum".to_string(),
        },
        ReplicaEvidenceState::Rejected { reason } => UnresolvedEvidenceRow {
            replica_id: Some(replica.replica_id),
            evidence_kind: UnresolvedEvidenceKind::ReplicaRejected,
            reason: format!("replica rejected original mutation: {reason}"),
        },
        ReplicaEvidenceState::SentWithoutAck { error } => UnresolvedEvidenceRow {
            replica_id: Some(replica.replica_id),
            evidence_kind: UnresolvedEvidenceKind::SentWithoutAck,
            reason: format!("mutation was sent without acknowledgement: {error}"),
        },
        ReplicaEvidenceState::NoSession { error } => UnresolvedEvidenceRow {
            replica_id: Some(replica.replica_id),
            evidence_kind: UnresolvedEvidenceKind::NoSession,
            reason: format!("mutation had no live session: {error}"),
        },
        ReplicaEvidenceState::NoSend { error } => UnresolvedEvidenceRow {
            replica_id: Some(replica.replica_id),
            evidence_kind: UnresolvedEvidenceKind::NoSend,
            reason: format!("mutation was not sent: {error}"),
        },
    }
}

fn local_rollback_unresolved_row(
    rollback: &LocalRollbackEvidence,
) -> Option<UnresolvedEvidenceRow> {
    match rollback {
        LocalRollbackEvidence::RestoredPreviousPayload
        | LocalRollbackEvidence::DeletedNewPayload => None,
        LocalRollbackEvidence::NotAttempted => Some(UnresolvedEvidenceRow {
            replica_id: None,
            evidence_kind: UnresolvedEvidenceKind::LocalRollbackIncomplete,
            reason: "local rollback was not attempted".to_string(),
        }),
        LocalRollbackEvidence::Failed { error } => Some(UnresolvedEvidenceRow {
            replica_id: None,
            evidence_kind: UnresolvedEvidenceKind::LocalRollbackIncomplete,
            reason: format!("local rollback failed: {error}"),
        }),
    }
}

fn compensating_unresolved_row(attempt: &CompensatingEvidence) -> Option<UnresolvedEvidenceRow> {
    match &attempt.outcome {
        CompensatingOutcome::Acknowledged => None,
        CompensatingOutcome::Rejected { reason } => Some(UnresolvedEvidenceRow {
            replica_id: Some(attempt.replica_id),
            evidence_kind: UnresolvedEvidenceKind::CompensatingRejected,
            reason: format!("compensating mutation was rejected: {reason}"),
        }),
        CompensatingOutcome::SentWithoutAck { error } => Some(UnresolvedEvidenceRow {
            replica_id: Some(attempt.replica_id),
            evidence_kind: UnresolvedEvidenceKind::CompensatingSentWithoutAck,
            reason: format!("compensating mutation was sent without acknowledgement: {error}"),
        }),
        CompensatingOutcome::NotSent { reason } => Some(UnresolvedEvidenceRow {
            replica_id: Some(attempt.replica_id),
            evidence_kind: UnresolvedEvidenceKind::CompensatingNotSent,
            reason: format!("compensating mutation was not sent: {reason}"),
        }),
    }
}

#[must_use]
pub fn covered_replica_ids(report: &FailedQuorumValidationReport) -> BTreeSet<u64> {
    report
        .unresolved_rows
        .iter()
        .filter_map(|row| row.replica_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario_with(states: Vec<ReplicaEvidenceState>) -> FailedQuorumScenario {
        FailedQuorumScenario {
            scenario_id: "failed-quorum-fixture".to_string(),
            mutation_id: "mutation-42".to_string(),
            quorum_size: 3,
            aggregate_ack_count: states
                .iter()
                .filter(|state| matches!(state, ReplicaEvidenceState::Acknowledged))
                .count(),
            replicas: states
                .into_iter()
                .enumerate()
                .map(|(idx, state)| ReplicaEvidence {
                    replica_id: idx as u64 + 1,
                    state,
                })
                .collect(),
            local_rollback: LocalRollbackEvidence::RestoredPreviousPayload,
            compensating_attempts: Vec::new(),
        }
    }

    #[test]
    fn failed_quorum_preserves_per_replica_uncertainty() {
        let scenario = scenario_with(vec![
            ReplicaEvidenceState::Acknowledged,
            ReplicaEvidenceState::SentWithoutAck {
                error: "timeout".to_string(),
            },
            ReplicaEvidenceState::NoSession {
                error: "partition".to_string(),
            },
        ]);

        let report = scenario.evaluate();

        assert!(report.has_unresolved_evidence());
        assert_eq!(covered_replica_ids(&report), BTreeSet::from([1, 2, 3]));
        assert!(report.unresolved_rows.iter().any(|row| {
            row.replica_id == Some(2) && row.evidence_kind == UnresolvedEvidenceKind::SentWithoutAck
        }));
        assert!(report.unresolved_rows.iter().any(|row| {
            row.replica_id == Some(3) && row.evidence_kind == UnresolvedEvidenceKind::NoSession
        }));
    }

    #[test]
    fn failed_quorum_rejects_aggregate_ack_success() {
        let mut scenario = scenario_with(vec![
            ReplicaEvidenceState::Acknowledged,
            ReplicaEvidenceState::Acknowledged,
            ReplicaEvidenceState::SentWithoutAck {
                error: "lost response".to_string(),
            },
        ]);
        scenario.quorum_size = 2;
        scenario.aggregate_ack_count = 2;

        let report = scenario.evaluate();

        assert!(report.aggregate_ack_count_reaches_quorum);
        assert!(report.has_unresolved_evidence());
        assert!(ClaimSurface::all_fail_closed_surfaces()
            .into_iter()
            .all(|surface| report.refuses_surface(surface)));
    }

    #[test]
    fn failed_quorum_covers_issue_1998_scenarios() {
        let scenario = FailedQuorumScenario {
            scenario_id: "issue-1998-row-shapes".to_string(),
            mutation_id: "mutation-1998".to_string(),
            quorum_size: 4,
            aggregate_ack_count: 1,
            replicas: vec![
                ReplicaEvidence {
                    replica_id: 10,
                    state: ReplicaEvidenceState::Acknowledged,
                },
                ReplicaEvidence {
                    replica_id: 11,
                    state: ReplicaEvidenceState::Rejected {
                        reason: "fence mismatch".to_string(),
                    },
                },
                ReplicaEvidence {
                    replica_id: 12,
                    state: ReplicaEvidenceState::SentWithoutAck {
                        error: "timeout".to_string(),
                    },
                },
                ReplicaEvidence {
                    replica_id: 13,
                    state: ReplicaEvidenceState::NoSession {
                        error: "partition".to_string(),
                    },
                },
                ReplicaEvidence {
                    replica_id: 14,
                    state: ReplicaEvidenceState::NoSend {
                        error: "admission refused".to_string(),
                    },
                },
            ],
            local_rollback: LocalRollbackEvidence::Failed {
                error: "primary restore failed".to_string(),
            },
            compensating_attempts: vec![
                CompensatingEvidence {
                    replica_id: 10,
                    outcome: CompensatingOutcome::Acknowledged,
                },
                CompensatingEvidence {
                    replica_id: 11,
                    outcome: CompensatingOutcome::Rejected {
                        reason: "fence mismatch".to_string(),
                    },
                },
                CompensatingEvidence {
                    replica_id: 12,
                    outcome: CompensatingOutcome::SentWithoutAck {
                        error: "timeout".to_string(),
                    },
                },
                CompensatingEvidence {
                    replica_id: 13,
                    outcome: CompensatingOutcome::NotSent {
                        reason: "no session".to_string(),
                    },
                },
            ],
        };

        let report = scenario.evaluate();
        let kinds = report
            .unresolved_rows
            .iter()
            .map(|row| row.evidence_kind)
            .collect::<BTreeSet<_>>();

        assert!(kinds.contains(&UnresolvedEvidenceKind::ReplicaAcknowledged));
        assert!(kinds.contains(&UnresolvedEvidenceKind::ReplicaRejected));
        assert!(kinds.contains(&UnresolvedEvidenceKind::SentWithoutAck));
        assert!(kinds.contains(&UnresolvedEvidenceKind::NoSession));
        assert!(kinds.contains(&UnresolvedEvidenceKind::NoSend));
        assert!(kinds.contains(&UnresolvedEvidenceKind::LocalRollbackIncomplete));
        assert!(kinds.contains(&UnresolvedEvidenceKind::CompensatingRejected));
        assert!(kinds.contains(&UnresolvedEvidenceKind::CompensatingSentWithoutAck));
        assert!(kinds.contains(&UnresolvedEvidenceKind::CompensatingNotSent));
    }

    #[test]
    fn failed_quorum_replay_preserves_unresolved_rows() {
        let scenario = scenario_with(vec![
            ReplicaEvidenceState::Acknowledged,
            ReplicaEvidenceState::NoSend {
                error: "backpressure".to_string(),
            },
        ]);

        let direct = scenario.evaluate();
        let replayed = replay_failed_quorum_report(&scenario).expect("serde replay succeeds");

        assert_eq!(direct, replayed);
        assert!(replayed.has_unresolved_evidence());
    }

    #[test]
    fn failed_quorum_claim_surfaces_fail_closed() {
        let scenario = scenario_with(vec![
            ReplicaEvidenceState::Rejected {
                reason: "membership fence".to_string(),
            },
            ReplicaEvidenceState::SentWithoutAck {
                error: "response lost".to_string(),
            },
        ]);

        let report = scenario.evaluate();

        assert_eq!(
            report.claim_refusals.len(),
            ClaimSurface::all_fail_closed_surfaces().len()
        );
        assert!(report.refuses_surface(ClaimSurface::DistributedTransactionClosure));
        assert!(report.refuses_surface(ClaimSurface::RepairCompletion));
        assert!(report.refuses_surface(ClaimSurface::ReleaseReadiness));
        assert!(report.refuses_surface(ClaimSurface::Production));
        assert!(report.refuses_surface(ClaimSurface::SuccessorComparator));
        assert!(report.refuses_surface(ClaimSurface::OpenZfsCeph));
        assert!(report.refuses_surface(ClaimSurface::RdmaCorrectness));
    }

    #[test]
    fn failed_quorum_consumer_refuses_unresolved_rows_until_1997() {
        let scenario = scenario_with(vec![ReplicaEvidenceState::SentWithoutAck {
            error: "timeout".to_string(),
        }]);

        let report = scenario.evaluate();
        let refusal = report
            .consumer_refusal
            .expect("unresolved evidence refuses consumer completion");

        assert_eq!(refusal.blocking_issue, 1997);
        assert_eq!(
            refusal.consumer,
            "scrub-repair failed-quorum ledger consumer"
        );
    }
}
