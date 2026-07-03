// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scheduler-side admission and checkpoint records for snapshot-pruner jobs.
//!
//! This module does not derive retention delete sets or reclaim evidence. It
//! records bounded due-dataset enumeration from explicit admission evidence and
//! produces the checkpointed handoff batch consumed by the snapshot-pruner job.

use alloc::{string::String, vec::Vec};

use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, WorkBudget,
};

const CURSOR_MAGIC: &[u8; 4] = b"SPS1";
const CURSOR_LEN: usize = 12;

/// Admission mode selected before the scheduler creates a pruner job handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotPrunerScheduleMode {
    DryRun { evidence: String },
    Destructive { evidence: String },
    Unavailable { reason: String },
}

impl SnapshotPrunerScheduleMode {
    #[must_use]
    pub fn dry_run(evidence: impl Into<String>) -> Self {
        Self::DryRun {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn destructive(evidence: impl Into<String>) -> Self {
        Self::Destructive {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }
}

/// One dataset candidate from dataset policy/catalog/lifecycle admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPrunerScheduleCandidate {
    pub dataset_name: String,
    pub due: bool,
    pub retention_policy_admitted: bool,
    pub mode: SnapshotPrunerScheduleMode,
    pub refusal: Option<SnapshotPrunerScheduleRefusal>,
}

impl SnapshotPrunerScheduleCandidate {
    #[must_use]
    pub fn due_dry_run(dataset_name: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            dataset_name: dataset_name.into(),
            due: true,
            retention_policy_admitted: true,
            mode: SnapshotPrunerScheduleMode::dry_run(evidence),
            refusal: None,
        }
    }

    #[must_use]
    pub fn due_destructive(dataset_name: impl Into<String>, evidence: impl Into<String>) -> Self {
        Self {
            dataset_name: dataset_name.into(),
            due: true,
            retention_policy_admitted: true,
            mode: SnapshotPrunerScheduleMode::destructive(evidence),
            refusal: None,
        }
    }

    #[must_use]
    pub fn refused(
        dataset_name: impl Into<String>,
        refusal: SnapshotPrunerScheduleRefusal,
    ) -> Self {
        Self {
            dataset_name: dataset_name.into(),
            due: false,
            retention_policy_admitted: false,
            mode: SnapshotPrunerScheduleMode::unavailable("snapshot-pruner admission refused"),
            refusal: Some(refusal),
        }
    }
}

/// Fail-closed reason emitted before a dataset reaches the pruner job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotPrunerScheduleRefusal {
    NotDue(String),
    RetentionPolicyUnavailable(String),
    DestructiveAdmissionUnavailable(String),
    UnsafeOrInapplicable(String),
}

/// Scheduler result for one dataset candidate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPrunerScheduleRecord {
    pub dataset_name: String,
    pub decision: SnapshotPrunerScheduleDecision,
}

/// Whether the scheduler emitted or refused a dataset handoff.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotPrunerScheduleDecision {
    HandoffDryRun { evidence: String },
    HandoffDestructive { evidence: String },
    Refused(SnapshotPrunerScheduleRefusal),
}

/// Bounded scheduler output for one enumeration tick.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPrunerScheduleBatch {
    pub checkpoint: Checkpoint,
    pub records: Vec<SnapshotPrunerScheduleRecord>,
    pub handoff_datasets: Vec<String>,
    pub is_complete: bool,
}

/// Crash-resumable due-dataset enumerator for `JobKind::SnapshotPruner`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPrunerScheduleState {
    job_id: JobId,
    candidates: Vec<SnapshotPrunerScheduleCandidate>,
    cursor: usize,
}

impl SnapshotPrunerScheduleState {
    #[must_use]
    pub fn new(job_id: JobId, candidates: Vec<SnapshotPrunerScheduleCandidate>) -> Self {
        Self {
            job_id,
            candidates,
            cursor: 0,
        }
    }

    pub fn from_checkpoint(
        candidates: Vec<SnapshotPrunerScheduleCandidate>,
        checkpoint: Checkpoint,
    ) -> Result<Self, JobError> {
        if checkpoint.job_kind != JobKind::SnapshotPruner {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "checkpoint is not for snapshot-pruner scheduling",
            });
        }
        let cursor = decode_cursor(checkpoint.job_id, &checkpoint.cursor_state)?;
        if cursor > candidates.len() {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "snapshot-pruner schedule cursor exceeds candidate set",
            });
        }
        Ok(Self {
            job_id: checkpoint.job_id,
            candidates,
            cursor,
        })
    }

    #[must_use]
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            job_id: self.job_id,
            job_kind: JobKind::SnapshotPruner,
            epoch: 1,
            cursor_state: encode_cursor(self.cursor),
            progress: JobProgress {
                items_processed: self.cursor as u64,
                items_total_estimate: self.candidates.len() as u64,
                bytes_processed: 0,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }

    pub fn enumerate_due(
        &mut self,
        budget: WorkBudget,
    ) -> Result<SnapshotPrunerScheduleBatch, JobError> {
        let remaining = self.candidates.len().saturating_sub(self.cursor);
        let limit = if budget.max_items == 0 {
            remaining
        } else {
            remaining.min(budget.max_items as usize)
        };
        if limit == 0 && remaining > 0 {
            return Err(JobError::BudgetExceeded {
                job_id: self.job_id,
                budget,
                actual_items: 1,
                actual_bytes: 0,
            });
        }

        let mut records = Vec::new();
        let mut handoff_datasets = Vec::new();
        for candidate in self.candidates[self.cursor..self.cursor + limit].iter() {
            let decision = classify_candidate(candidate);
            if matches!(
                decision,
                SnapshotPrunerScheduleDecision::HandoffDryRun { .. }
                    | SnapshotPrunerScheduleDecision::HandoffDestructive { .. }
            ) {
                handoff_datasets.push(candidate.dataset_name.clone());
            }
            records.push(SnapshotPrunerScheduleRecord {
                dataset_name: candidate.dataset_name.clone(),
                decision,
            });
        }
        self.cursor += limit;

        Ok(SnapshotPrunerScheduleBatch {
            checkpoint: self.checkpoint(),
            records,
            handoff_datasets,
            is_complete: self.cursor >= self.candidates.len(),
        })
    }
}

fn classify_candidate(
    candidate: &SnapshotPrunerScheduleCandidate,
) -> SnapshotPrunerScheduleDecision {
    if let Some(refusal) = candidate.refusal.clone() {
        return SnapshotPrunerScheduleDecision::Refused(refusal);
    }
    if !candidate.due {
        return SnapshotPrunerScheduleDecision::Refused(SnapshotPrunerScheduleRefusal::NotDue(
            "snapshot-pruner cadence is not due".into(),
        ));
    }
    if !candidate.retention_policy_admitted {
        return SnapshotPrunerScheduleDecision::Refused(
            SnapshotPrunerScheduleRefusal::RetentionPolicyUnavailable(
                "snapshot retention policy admission missing".into(),
            ),
        );
    }
    match &candidate.mode {
        SnapshotPrunerScheduleMode::DryRun { evidence } => {
            SnapshotPrunerScheduleDecision::HandoffDryRun {
                evidence: evidence.clone(),
            }
        }
        SnapshotPrunerScheduleMode::Destructive { evidence } => {
            SnapshotPrunerScheduleDecision::HandoffDestructive {
                evidence: evidence.clone(),
            }
        }
        SnapshotPrunerScheduleMode::Unavailable { reason } => {
            SnapshotPrunerScheduleDecision::Refused(
                SnapshotPrunerScheduleRefusal::DestructiveAdmissionUnavailable(reason.clone()),
            )
        }
    }
}

fn encode_cursor(cursor: usize) -> CursorState {
    let mut bytes = Vec::with_capacity(CURSOR_LEN);
    bytes.extend_from_slice(CURSOR_MAGIC);
    bytes.extend_from_slice(&(cursor as u64).to_le_bytes());
    CursorState(bytes)
}

fn decode_cursor(job_id: JobId, cursor: &CursorState) -> Result<usize, JobError> {
    if cursor.is_empty() {
        return Ok(0);
    }
    if cursor.as_bytes().len() != CURSOR_LEN || &cursor.as_bytes()[..4] != CURSOR_MAGIC {
        return Err(JobError::CursorStateInvalid {
            job_id,
            reason: "snapshot-pruner schedule cursor is corrupt",
        });
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&cursor.as_bytes()[4..]);
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| JobError::CursorStateInvalid {
        job_id,
        reason: "snapshot-pruner schedule cursor does not fit usize",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_enumeration_emits_due_handoffs_and_refusals() {
        let candidates = vec![
            SnapshotPrunerScheduleCandidate::due_dry_run("dry", "operator dry-run"),
            SnapshotPrunerScheduleCandidate::due_destructive("destroy", "destructive admitted"),
            SnapshotPrunerScheduleCandidate::refused(
                "blocked",
                SnapshotPrunerScheduleRefusal::UnsafeOrInapplicable("lifecycle stale".into()),
            ),
        ];
        let mut state = SnapshotPrunerScheduleState::new(JobId(41), candidates);

        let batch = state
            .enumerate_due(WorkBudget {
                max_items: 2,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();

        assert!(!batch.is_complete);
        assert_eq!(batch.handoff_datasets, vec!["dry", "destroy"]);
        assert_eq!(batch.records.len(), 2);
        assert_eq!(batch.checkpoint.job_kind, JobKind::SnapshotPruner);
        assert_eq!(batch.checkpoint.progress.items_processed, 2);

        let batch = state
            .enumerate_due(WorkBudget {
                max_items: 2,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(batch.is_complete);
        assert!(batch.handoff_datasets.is_empty());
        assert!(matches!(
            batch.records[0].decision,
            SnapshotPrunerScheduleDecision::Refused(
                SnapshotPrunerScheduleRefusal::UnsafeOrInapplicable(_)
            )
        ));
    }

    #[test]
    fn checkpoint_resume_skips_already_enumerated_candidates() {
        let candidates = vec![
            SnapshotPrunerScheduleCandidate::due_dry_run("first", "dry-run"),
            SnapshotPrunerScheduleCandidate::due_dry_run("second", "dry-run"),
        ];
        let mut state = SnapshotPrunerScheduleState::new(JobId(42), candidates.clone());
        let first = state
            .enumerate_due(WorkBudget {
                max_items: 1,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();

        let mut resumed =
            SnapshotPrunerScheduleState::from_checkpoint(candidates, first.checkpoint).unwrap();
        assert_eq!(resumed.cursor(), 1);

        let second = resumed
            .enumerate_due(WorkBudget {
                max_items: 1,
                max_bytes: 0,
                max_ms: 0,
            })
            .unwrap();
        assert!(second.is_complete);
        assert_eq!(second.handoff_datasets, vec!["second"]);
    }

    #[test]
    fn unsafe_or_missing_inputs_are_reported_not_silently_skipped() {
        let mut missing_policy =
            SnapshotPrunerScheduleCandidate::due_dry_run("missing-policy", "dry-run");
        missing_policy.retention_policy_admitted = false;
        let mut missing_mode =
            SnapshotPrunerScheduleCandidate::due_dry_run("missing-mode", "dry-run");
        missing_mode.mode = SnapshotPrunerScheduleMode::unavailable("operator mode missing");
        let mut not_due = SnapshotPrunerScheduleCandidate::due_dry_run("not-due", "dry-run");
        not_due.due = false;
        let mut state = SnapshotPrunerScheduleState::new(
            JobId(43),
            vec![missing_policy, missing_mode, not_due],
        );

        let batch = state.enumerate_due(WorkBudget::default()).unwrap();

        assert!(batch.is_complete);
        assert!(batch.handoff_datasets.is_empty());
        assert!(matches!(
            batch.records[0].decision,
            SnapshotPrunerScheduleDecision::Refused(
                SnapshotPrunerScheduleRefusal::RetentionPolicyUnavailable(_)
            )
        ));
        assert!(matches!(
            batch.records[1].decision,
            SnapshotPrunerScheduleDecision::Refused(
                SnapshotPrunerScheduleRefusal::DestructiveAdmissionUnavailable(_)
            )
        ));
        assert!(matches!(
            batch.records[2].decision,
            SnapshotPrunerScheduleDecision::Refused(SnapshotPrunerScheduleRefusal::NotDue(_))
        ));
    }

    #[test]
    fn corrupt_checkpoint_refuses_resume() {
        let checkpoint = Checkpoint {
            job_id: JobId(44),
            job_kind: JobKind::SnapshotPruner,
            epoch: 1,
            cursor_state: CursorState(vec![1, 2, 3]),
            progress: JobProgress::default(),
        };

        let err = SnapshotPrunerScheduleState::from_checkpoint(Vec::new(), checkpoint).unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));
    }
}
