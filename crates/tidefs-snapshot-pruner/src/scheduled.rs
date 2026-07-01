// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Scheduled snapshot-pruner job adapter for the background scheduler.
//!
//! This module consumes explicit dataset admission evidence supplied by the
//! scheduler integration layer. Dataset policy, catalog, lifecycle, and
//! operator-control surfaces remain outside this crate; missing inputs are
//! represented as typed refusal evidence instead of defaulting to deletion.

use std::time::SystemTime;

use tidefs_incremental_job_core::IncrementalJob;
use tidefs_local_object_store::LocalObjectStore;
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

use crate::{PruneResult, SnapshotPruner, SnapshotRetentionPolicy};

const CURSOR_MAGIC: &[u8; 4] = b"SPJ1";
const CURSOR_LEN: usize = 12;

/// Explicit cadence evidence for one scheduled-prune dataset candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotPrunerCadenceEvidence {
    Due { evidence: String },
    NotDue { evidence: String },
    Unavailable { reason: String },
}

impl SnapshotPrunerCadenceEvidence {
    #[must_use]
    pub fn due(evidence: impl Into<String>) -> Self {
        Self::Due {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn missing(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }
}

/// Catalog freshness evidence consumed by the scheduled pruner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerCatalogEvidence {
    Fresh { evidence: String },
    Missing { reason: String },
    Stale { reason: String },
}

impl ScheduledSnapshotPrunerCatalogEvidence {
    #[must_use]
    pub fn fresh(evidence: impl Into<String>) -> Self {
        Self::Fresh {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn missing(reason: impl Into<String>) -> Self {
        Self::Missing {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn stale(reason: impl Into<String>) -> Self {
        Self::Stale {
            reason: reason.into(),
        }
    }
}

/// Lifecycle eligibility evidence consumed by the scheduled pruner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerLifecycleEvidence {
    Eligible { evidence: String },
    Missing { reason: String },
    Stale { reason: String },
    Ineligible { reason: String },
}

impl ScheduledSnapshotPrunerLifecycleEvidence {
    #[must_use]
    pub fn eligible(evidence: impl Into<String>) -> Self {
        Self::Eligible {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn missing(reason: impl Into<String>) -> Self {
        Self::Missing {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn stale(reason: impl Into<String>) -> Self {
        Self::Stale {
            reason: reason.into(),
        }
    }

    #[must_use]
    pub fn ineligible(reason: impl Into<String>) -> Self {
        Self::Ineligible {
            reason: reason.into(),
        }
    }
}

/// Same-dataset mutation conflict evidence visible to the scheduler layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerMutationEvidence {
    NoConflict,
    Conflict { owner: String },
}

impl ScheduledSnapshotPrunerMutationEvidence {
    #[must_use]
    pub fn conflict(owner: impl Into<String>) -> Self {
        Self::Conflict {
            owner: owner.into(),
        }
    }
}

/// Explicit destructive-mode admission evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerDestructiveAdmission {
    DryRunOnly { evidence: String },
    Destroy { evidence: String },
    Unavailable { reason: String },
}

impl ScheduledSnapshotPrunerDestructiveAdmission {
    #[must_use]
    pub fn dry_run(evidence: impl Into<String>) -> Self {
        Self::DryRunOnly {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn destroy(evidence: impl Into<String>) -> Self {
        Self::Destroy {
            evidence: evidence.into(),
        }
    }

    #[must_use]
    pub fn missing(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
        }
    }
}

/// One dataset entry supplied to a scheduled snapshot-pruner job.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledSnapshotPrunerDataset {
    pub dataset_name: String,
    pub retention_policy: Option<SnapshotRetentionPolicy>,
    pub cadence: SnapshotPrunerCadenceEvidence,
    pub destructive_admission: ScheduledSnapshotPrunerDestructiveAdmission,
    pub catalog: ScheduledSnapshotPrunerCatalogEvidence,
    pub lifecycle: ScheduledSnapshotPrunerLifecycleEvidence,
    pub mutation: ScheduledSnapshotPrunerMutationEvidence,
}

impl ScheduledSnapshotPrunerDataset {
    #[must_use]
    pub fn due_dry_run(
        dataset_name: impl Into<String>,
        retention_policy: SnapshotRetentionPolicy,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            dataset_name: dataset_name.into(),
            retention_policy: Some(retention_policy),
            cadence: SnapshotPrunerCadenceEvidence::due("cadence due"),
            destructive_admission: ScheduledSnapshotPrunerDestructiveAdmission::dry_run(evidence),
            catalog: ScheduledSnapshotPrunerCatalogEvidence::fresh("catalog fresh"),
            lifecycle: ScheduledSnapshotPrunerLifecycleEvidence::eligible("lifecycle eligible"),
            mutation: ScheduledSnapshotPrunerMutationEvidence::NoConflict,
        }
    }

    #[must_use]
    pub fn due_destructive(
        dataset_name: impl Into<String>,
        retention_policy: SnapshotRetentionPolicy,
        evidence: impl Into<String>,
    ) -> Self {
        Self {
            dataset_name: dataset_name.into(),
            retention_policy: Some(retention_policy),
            cadence: SnapshotPrunerCadenceEvidence::due("cadence due"),
            destructive_admission: ScheduledSnapshotPrunerDestructiveAdmission::destroy(evidence),
            catalog: ScheduledSnapshotPrunerCatalogEvidence::fresh("catalog fresh"),
            lifecycle: ScheduledSnapshotPrunerLifecycleEvidence::eligible("lifecycle eligible"),
            mutation: ScheduledSnapshotPrunerMutationEvidence::NoConflict,
        }
    }
}

/// Typed fail-closed refusal evidence emitted by the scheduled pruner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerRefusal {
    CadenceUnavailable(String),
    CadenceNotDue(String),
    RetentionPolicyUnavailable(String),
    CatalogUnavailable(String),
    CatalogStale(String),
    LifecycleUnavailable(String),
    LifecycleStale(String),
    LifecycleIneligible(String),
    MutationConflict(String),
    DestructiveAdmissionUnavailable(String),
    DestructiveDeletionRefused {
        snapshot_name: String,
        reason: String,
    },
}

/// Outcome class for one scheduled dataset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerOutcome {
    Refused,
    PlannedDryRun,
    CompletedDestructive,
}

/// Result of handing one planned deletion to the selected deletion authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledSnapshotPrunerDestructiveHandoffResult {
    Destroyed,
    Refused(String),
}

/// Evidence that one planned snapshot deletion was handed to the selected
/// snapshot deletion authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledSnapshotPrunerDestructiveHandoff {
    pub snapshot_name: String,
    pub result: ScheduledSnapshotPrunerDestructiveHandoffResult,
}

/// Result/refusal evidence for one scheduled dataset.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScheduledSnapshotPrunerRecord {
    pub dataset_name: String,
    pub outcome: ScheduledSnapshotPrunerOutcome,
    pub refusals: Vec<ScheduledSnapshotPrunerRefusal>,
    pub plan: Option<PruneResult>,
    pub destructive_handoffs: Vec<ScheduledSnapshotPrunerDestructiveHandoff>,
}

/// Crash-resumable scheduled snapshot-pruner job.
#[derive(Debug)]
pub struct ScheduledSnapshotPrunerJob {
    job_id: JobId,
    store: LocalObjectStore,
    datasets: Vec<ScheduledSnapshotPrunerDataset>,
    cursor: usize,
    now: SystemTime,
    records: Vec<ScheduledSnapshotPrunerRecord>,
    completed: bool,
}

impl ScheduledSnapshotPrunerJob {
    #[must_use]
    pub fn new(
        job_id: JobId,
        store: LocalObjectStore,
        datasets: Vec<ScheduledSnapshotPrunerDataset>,
        now: SystemTime,
    ) -> Self {
        Self {
            job_id,
            store,
            datasets,
            cursor: 0,
            now,
            records: Vec::new(),
            completed: false,
        }
    }

    pub fn from_checkpoint(
        store: LocalObjectStore,
        datasets: Vec<ScheduledSnapshotPrunerDataset>,
        now: SystemTime,
        checkpoint: Checkpoint,
        records: Vec<ScheduledSnapshotPrunerRecord>,
    ) -> Result<Self, JobError> {
        if checkpoint.job_kind != JobKind::SnapshotPruner {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "checkpoint is not for snapshot-pruner",
            });
        }
        let cursor = decode_cursor(checkpoint.job_id, &checkpoint.cursor_state)?;
        if cursor > datasets.len() {
            return Err(JobError::CursorStateInvalid {
                job_id: checkpoint.job_id,
                reason: "snapshot-pruner cursor exceeds dataset work set",
            });
        }
        let completed = cursor >= datasets.len();
        Ok(Self {
            job_id: checkpoint.job_id,
            store,
            datasets,
            cursor,
            now,
            records,
            completed,
        })
    }

    #[must_use]
    pub fn records(&self) -> &[ScheduledSnapshotPrunerRecord] {
        &self.records
    }

    #[must_use]
    pub fn store(&self) -> &LocalObjectStore {
        &self.store
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
                items_total_estimate: self.datasets.len() as u64,
                bytes_processed: 0,
                bytes_total_estimate: 0,
                elapsed_ms: 0,
            },
        }
    }

    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        LocalObjectStore,
        Vec<ScheduledSnapshotPrunerDataset>,
        Vec<ScheduledSnapshotPrunerRecord>,
    ) {
        (self.store, self.datasets, self.records)
    }

    fn process_dataset(
        &mut self,
        dataset: &ScheduledSnapshotPrunerDataset,
    ) -> ScheduledSnapshotPrunerRecord {
        let mut refusals = admission_refusals(dataset);
        let may_plan = refusals.iter().all(|refusal| {
            matches!(
                refusal,
                ScheduledSnapshotPrunerRefusal::DestructiveAdmissionUnavailable(_)
            )
        });

        if !may_plan {
            return ScheduledSnapshotPrunerRecord {
                dataset_name: dataset.dataset_name.clone(),
                outcome: ScheduledSnapshotPrunerOutcome::Refused,
                refusals,
                plan: None,
                destructive_handoffs: Vec::new(),
            };
        }

        let Some(policy) = dataset.retention_policy.clone() else {
            return ScheduledSnapshotPrunerRecord {
                dataset_name: dataset.dataset_name.clone(),
                outcome: ScheduledSnapshotPrunerOutcome::Refused,
                refusals: vec![ScheduledSnapshotPrunerRefusal::RetentionPolicyUnavailable(
                    "snapshot retention policy admission missing".into(),
                )],
                plan: None,
                destructive_handoffs: Vec::new(),
            };
        };

        let mut pruner = SnapshotPruner::load(&self.store, policy);
        let plan = pruner.plan_dataset_prune(&self.store, &dataset.dataset_name, self.now);
        let delete_set = plan.delete_set.clone();

        match &dataset.destructive_admission {
            ScheduledSnapshotPrunerDestructiveAdmission::Destroy { .. } => {
                let mut handoffs = Vec::new();
                for snapshot_name in delete_set {
                    let result = match pruner.destroy_snapshot(
                        &mut self.store,
                        &dataset.dataset_name,
                        &snapshot_name,
                    ) {
                        Ok(_) => ScheduledSnapshotPrunerDestructiveHandoffResult::Destroyed,
                        Err(err) => {
                            let reason = err.to_string();
                            refusals.push(
                                ScheduledSnapshotPrunerRefusal::DestructiveDeletionRefused {
                                    snapshot_name: snapshot_name.clone(),
                                    reason: reason.clone(),
                                },
                            );
                            ScheduledSnapshotPrunerDestructiveHandoffResult::Refused(reason)
                        }
                    };
                    handoffs.push(ScheduledSnapshotPrunerDestructiveHandoff {
                        snapshot_name,
                        result,
                    });
                }
                let outcome = if refusals.is_empty() {
                    ScheduledSnapshotPrunerOutcome::CompletedDestructive
                } else {
                    ScheduledSnapshotPrunerOutcome::Refused
                };
                ScheduledSnapshotPrunerRecord {
                    dataset_name: dataset.dataset_name.clone(),
                    outcome,
                    refusals,
                    plan: Some(plan),
                    destructive_handoffs: handoffs,
                }
            }
            ScheduledSnapshotPrunerDestructiveAdmission::DryRunOnly { .. }
            | ScheduledSnapshotPrunerDestructiveAdmission::Unavailable { .. } => {
                let outcome = if refusals.is_empty() {
                    ScheduledSnapshotPrunerOutcome::PlannedDryRun
                } else {
                    ScheduledSnapshotPrunerOutcome::Refused
                };
                ScheduledSnapshotPrunerRecord {
                    dataset_name: dataset.dataset_name.clone(),
                    outcome,
                    refusals,
                    plan: Some(plan),
                    destructive_handoffs: Vec::new(),
                }
            }
        }
    }
}

impl IncrementalJob for ScheduledSnapshotPrunerJob {
    fn resume(_state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        Err(JobError::Other(
            "ScheduledSnapshotPrunerJob requires explicit store and admission reconstruction"
                .into(),
        ))
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if self.completed {
            return Err(JobError::JobAlreadyComplete {
                job_id: self.job_id,
            });
        }

        let max_items = if budget.max_items == 0 {
            usize::MAX
        } else {
            usize::try_from(budget.max_items).unwrap_or(usize::MAX)
        };

        let mut processed = 0usize;
        while processed < max_items && self.cursor < self.datasets.len() {
            let dataset = self.datasets[self.cursor].clone();
            let record = self.process_dataset(&dataset);
            self.records.push(record);
            self.cursor = self.cursor.saturating_add(1);
            processed = processed.saturating_add(1);
        }

        let checkpoint = self.checkpoint();
        if self.cursor >= self.datasets.len() {
            self.completed = true;
            Ok(StepResult::complete(checkpoint))
        } else {
            Ok(StepResult::in_progress(checkpoint))
        }
    }

    fn persist_checkpoint(&self, _checkpoint: &Checkpoint) -> Result<(), JobError> {
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        Ok(())
    }

    fn job_id(&self) -> JobId {
        self.job_id
    }

    fn job_kind(&self) -> JobKind {
        JobKind::SnapshotPruner
    }
}

fn admission_refusals(
    dataset: &ScheduledSnapshotPrunerDataset,
) -> Vec<ScheduledSnapshotPrunerRefusal> {
    let mut refusals = Vec::new();

    match &dataset.cadence {
        SnapshotPrunerCadenceEvidence::Due { .. } => {}
        SnapshotPrunerCadenceEvidence::NotDue { evidence } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::CadenceNotDue(
                evidence.clone(),
            ));
        }
        SnapshotPrunerCadenceEvidence::Unavailable { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::CadenceUnavailable(
                reason.clone(),
            ));
        }
    }

    if dataset.retention_policy.is_none() {
        refusals.push(ScheduledSnapshotPrunerRefusal::RetentionPolicyUnavailable(
            "snapshot retention policy admission missing".into(),
        ));
    }

    match &dataset.catalog {
        ScheduledSnapshotPrunerCatalogEvidence::Fresh { .. } => {}
        ScheduledSnapshotPrunerCatalogEvidence::Missing { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::CatalogUnavailable(
                reason.clone(),
            ));
        }
        ScheduledSnapshotPrunerCatalogEvidence::Stale { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::CatalogStale(reason.clone()));
        }
    }

    match &dataset.lifecycle {
        ScheduledSnapshotPrunerLifecycleEvidence::Eligible { .. } => {}
        ScheduledSnapshotPrunerLifecycleEvidence::Missing { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::LifecycleUnavailable(
                reason.clone(),
            ));
        }
        ScheduledSnapshotPrunerLifecycleEvidence::Stale { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::LifecycleStale(
                reason.clone(),
            ));
        }
        ScheduledSnapshotPrunerLifecycleEvidence::Ineligible { reason } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::LifecycleIneligible(
                reason.clone(),
            ));
        }
    }

    match &dataset.mutation {
        ScheduledSnapshotPrunerMutationEvidence::NoConflict => {}
        ScheduledSnapshotPrunerMutationEvidence::Conflict { owner } => {
            refusals.push(ScheduledSnapshotPrunerRefusal::MutationConflict(
                owner.clone(),
            ));
        }
    }

    match &dataset.destructive_admission {
        ScheduledSnapshotPrunerDestructiveAdmission::DryRunOnly { .. }
        | ScheduledSnapshotPrunerDestructiveAdmission::Destroy { .. } => {}
        ScheduledSnapshotPrunerDestructiveAdmission::Unavailable { reason } => {
            refusals.push(
                ScheduledSnapshotPrunerRefusal::DestructiveAdmissionUnavailable(reason.clone()),
            );
        }
    }

    refusals
}

fn encode_cursor(cursor: usize) -> CursorState {
    let mut bytes = Vec::with_capacity(CURSOR_LEN);
    bytes.extend_from_slice(CURSOR_MAGIC);
    bytes.extend_from_slice(&(cursor as u64).to_le_bytes());
    CursorState(bytes)
}

fn decode_cursor(job_id: JobId, cursor_state: &CursorState) -> Result<usize, JobError> {
    if cursor_state.is_empty() {
        return Ok(0);
    }
    if cursor_state.len() != CURSOR_LEN || &cursor_state.as_bytes()[..4] != CURSOR_MAGIC {
        return Err(JobError::CursorStateInvalid {
            job_id,
            reason: "snapshot-pruner cursor header invalid",
        });
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&cursor_state.as_bytes()[4..12]);
    usize::try_from(u64::from_le_bytes(raw)).map_err(|_| JobError::CursorStateInvalid {
        job_id,
        reason: "snapshot-pruner cursor overflows usize",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn temp_store(name: &str) -> (std::path::PathBuf, LocalObjectStore) {
        let dir = std::env::temp_dir().join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        (dir.clone(), LocalObjectStore::open(&dir).unwrap())
    }

    fn retention_delete_all() -> SnapshotRetentionPolicy {
        SnapshotRetentionPolicy {
            keep_last: Some(0),
            ..Default::default()
        }
    }

    fn record_empty_pin_evidence(
        pruner: &SnapshotPruner,
        store: &mut LocalObjectStore,
        dataset: &str,
        snapshots: &[&str],
    ) {
        for snapshot in snapshots {
            pruner
                .record_snapshot_pin_evidence(store, dataset, snapshot, Vec::new(), Vec::new())
                .unwrap();
        }
    }

    #[test]
    fn admission_refusals_are_typed_and_fail_closed() {
        let (dir, store) = temp_store("tidefs-scheduled-pruner-refusals");
        let dataset = ScheduledSnapshotPrunerDataset {
            dataset_name: "ds".into(),
            retention_policy: Some(retention_delete_all()),
            cadence: SnapshotPrunerCadenceEvidence::missing("cadence property missing"),
            destructive_admission: ScheduledSnapshotPrunerDestructiveAdmission::missing(
                "destructive mode missing",
            ),
            catalog: ScheduledSnapshotPrunerCatalogEvidence::stale("catalog watermark stale"),
            lifecycle: ScheduledSnapshotPrunerLifecycleEvidence::missing("lifecycle missing"),
            mutation: ScheduledSnapshotPrunerMutationEvidence::conflict("snapshot-create"),
        };
        let mut job = ScheduledSnapshotPrunerJob::new(
            JobId(11),
            store,
            vec![dataset],
            UNIX_EPOCH + Duration::from_secs(10),
        );

        let step = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(step.is_complete);
        let record = &job.records()[0];
        assert_eq!(record.outcome, ScheduledSnapshotPrunerOutcome::Refused);
        assert!(record.plan.is_none());
        assert!(record.refusals.iter().any(|reason| matches!(
            reason,
            ScheduledSnapshotPrunerRefusal::CadenceUnavailable(_)
        )));
        assert!(record.refusals.iter().any(|reason| matches!(
            reason,
            ScheduledSnapshotPrunerRefusal::DestructiveAdmissionUnavailable(_)
        )));
        assert!(record
            .refusals
            .iter()
            .any(|reason| matches!(reason, ScheduledSnapshotPrunerRefusal::CatalogStale(_))));
        assert!(record.refusals.iter().any(|reason| matches!(
            reason,
            ScheduledSnapshotPrunerRefusal::LifecycleUnavailable(_)
        )));
        assert!(record
            .refusals
            .iter()
            .any(|reason| matches!(reason, ScheduledSnapshotPrunerRefusal::MutationConflict(_))));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dry_run_uses_pruner_planning_authority_without_destroying() {
        let (dir, mut store) = temp_store("tidefs-scheduled-pruner-dry-run");
        store.create_snapshot("ds", "snap-0").unwrap();
        store.create_snapshot("ds", "snap-1").unwrap();
        let pruner = SnapshotPruner::new(retention_delete_all());
        record_empty_pin_evidence(&pruner, &mut store, "ds", &["snap-0", "snap-1"]);

        let dataset = ScheduledSnapshotPrunerDataset::due_dry_run(
            "ds",
            retention_delete_all(),
            "explicit dry-run mode",
        );
        let mut job = ScheduledSnapshotPrunerJob::new(
            JobId(12),
            store,
            vec![dataset],
            UNIX_EPOCH + Duration::from_secs(10),
        );

        let step = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(step.is_complete);
        let record = &job.records()[0];
        assert_eq!(
            record.outcome,
            ScheduledSnapshotPrunerOutcome::PlannedDryRun
        );
        assert!(record.refusals.is_empty());
        assert_eq!(record.plan.as_ref().unwrap().delete_set.len(), 2);
        assert!(record.destructive_handoffs.is_empty());
        assert_eq!(job.store().list_snapshots("ds").len(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn missing_destructive_admission_records_refusal_without_handoff() {
        let (dir, mut store) = temp_store("tidefs-scheduled-pruner-missing-destructive");
        store.create_snapshot("ds", "snap-0").unwrap();
        store.create_snapshot("ds", "snap-1").unwrap();
        let pruner = SnapshotPruner::new(retention_delete_all());
        record_empty_pin_evidence(&pruner, &mut store, "ds", &["snap-0", "snap-1"]);

        let mut dataset =
            ScheduledSnapshotPrunerDataset::due_dry_run("ds", retention_delete_all(), "dry-run");
        dataset.destructive_admission =
            ScheduledSnapshotPrunerDestructiveAdmission::missing("destructive mode missing");
        let mut job = ScheduledSnapshotPrunerJob::new(
            JobId(16),
            store,
            vec![dataset],
            UNIX_EPOCH + Duration::from_secs(10),
        );

        let step = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(step.is_complete);
        let record = &job.records()[0];
        assert_eq!(record.outcome, ScheduledSnapshotPrunerOutcome::Refused);
        assert!(record.refusals.iter().any(|reason| matches!(
            reason,
            ScheduledSnapshotPrunerRefusal::DestructiveAdmissionUnavailable(_)
        )));
        assert_eq!(record.plan.as_ref().unwrap().delete_set.len(), 2);
        assert!(record.destructive_handoffs.is_empty());
        assert_eq!(job.store().list_snapshots("ds").len(), 2);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn destructive_admission_hands_planned_deletes_to_snapshot_authority() {
        let (dir, mut store) = temp_store("tidefs-scheduled-pruner-destructive");
        store.create_snapshot("ds", "snap-0").unwrap();
        store.create_snapshot("ds", "snap-1").unwrap();
        let pruner = SnapshotPruner::new(retention_delete_all());
        record_empty_pin_evidence(&pruner, &mut store, "ds", &["snap-0", "snap-1"]);

        let dataset = ScheduledSnapshotPrunerDataset::due_destructive(
            "ds",
            retention_delete_all(),
            "explicit destructive admission",
        );
        let mut job = ScheduledSnapshotPrunerJob::new(
            JobId(13),
            store,
            vec![dataset],
            UNIX_EPOCH + Duration::from_secs(10),
        );

        let step = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(step.is_complete);
        let record = &job.records()[0];
        assert_eq!(
            record.outcome,
            ScheduledSnapshotPrunerOutcome::CompletedDestructive
        );
        assert_eq!(record.destructive_handoffs.len(), 2);
        assert!(record.destructive_handoffs.iter().all(|handoff| matches!(
            handoff.result,
            ScheduledSnapshotPrunerDestructiveHandoffResult::Destroyed
        )));
        assert!(job.store().list_snapshots("ds").is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn resume_skips_checkpointed_datasets_without_duplicate_evidence_or_handoffs() {
        let (dir, mut store) = temp_store("tidefs-scheduled-pruner-resume");
        store.create_snapshot("first", "snap-0").unwrap();
        store.create_snapshot("second", "snap-0").unwrap();
        let pruner = SnapshotPruner::new(retention_delete_all());
        record_empty_pin_evidence(&pruner, &mut store, "first", &["snap-0"]);
        record_empty_pin_evidence(&pruner, &mut store, "second", &["snap-0"]);

        let datasets = vec![
            ScheduledSnapshotPrunerDataset::due_destructive(
                "first",
                retention_delete_all(),
                "explicit destructive admission",
            ),
            ScheduledSnapshotPrunerDataset::due_destructive(
                "second",
                retention_delete_all(),
                "explicit destructive admission",
            ),
        ];
        let mut job = ScheduledSnapshotPrunerJob::new(
            JobId(14),
            store,
            datasets,
            UNIX_EPOCH + Duration::from_secs(10),
        );

        let step = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(!step.is_complete);
        assert_eq!(job.records().len(), 1);
        assert!(job.store().list_snapshots("first").is_empty());
        assert_eq!(job.store().list_snapshots("second").len(), 1);

        let checkpoint = step.checkpoint;
        let (store, datasets, records) = job.into_parts();
        let mut resumed = ScheduledSnapshotPrunerJob::from_checkpoint(
            store,
            datasets,
            UNIX_EPOCH + Duration::from_secs(10),
            checkpoint,
            records,
        )
        .unwrap();

        let step = resumed
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        assert!(step.is_complete);
        assert_eq!(resumed.records().len(), 2);
        assert_eq!(
            resumed
                .records()
                .iter()
                .flat_map(|record| record.destructive_handoffs.iter())
                .count(),
            2
        );
        assert!(resumed.store().list_snapshots("first").is_empty());
        assert!(resumed.store().list_snapshots("second").is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn corrupt_cursor_refuses_resume() {
        let (dir, store) = temp_store("tidefs-scheduled-pruner-corrupt-cursor");
        let checkpoint = Checkpoint {
            job_id: JobId(15),
            job_kind: JobKind::SnapshotPruner,
            epoch: 1,
            cursor_state: CursorState(vec![1, 2, 3]),
            progress: JobProgress::default(),
        };

        let err = ScheduledSnapshotPrunerJob::from_checkpoint(
            store,
            Vec::new(),
            UNIX_EPOCH,
            checkpoint,
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, JobError::CursorStateInvalid { .. }));

        let _ = std::fs::remove_dir_all(dir);
    }
}
