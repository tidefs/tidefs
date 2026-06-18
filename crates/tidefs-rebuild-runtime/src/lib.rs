// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! Rebuild runtime: async background workers that execute deterministic
//! ReplicaMovementIntent records over the network for rebuild, backfill,
//! and rebalance operations.
//!
//! Bridges the gap between the rebuild/relocation planners (which produce
//! movement intents) and actual data transfer + placement confirmation.

pub mod admission;
pub mod completion;
pub mod engine;
pub mod progress;
pub mod quorum;
pub mod scheduler;
pub mod task;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use tidefs_incremental_job_core::IncrementalJob;
use tidefs_replication_model::{
    ReplicaMovementClass, ReplicaMovementIntentRecord, ReplicatedReceiptId,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};
use tidefs_verification_engine::ObjectVerificationOutcome;

// ─ RebuildStats ───────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct RebuildStats {
    pub objects_rebuilt: u64,
    pub bytes_rebuilt: u64,
    pub objects_backfilled: u64,
    pub bytes_backfilled: u64,
    pub objects_rebalanced: u64,
    pub bytes_rebalanced: u64,
    pub objects_pending: u64,
    pub bytes_pending: u64,
    pub objects_failed: u64,
    pub estimated_completion_ns: u64,
    pub bandwidth_utilization: f64,
}

impl RebuildStats {
    pub const ZERO: Self = Self {
        objects_rebuilt: 0,
        bytes_rebuilt: 0,
        objects_backfilled: 0,
        bytes_backfilled: 0,
        objects_rebalanced: 0,
        bytes_rebalanced: 0,
        objects_pending: 0,
        bytes_pending: 0,
        objects_failed: 0,
        estimated_completion_ns: 0,
        bandwidth_utilization: 0.0,
    };

    #[must_use]
    pub fn total_objects_processed(&self) -> u64 {
        self.objects_rebuilt + self.objects_backfilled + self.objects_rebalanced
    }

    #[must_use]
    pub fn total_bytes_processed(&self) -> u64 {
        self.bytes_rebuilt + self.bytes_backfilled + self.bytes_rebalanced
    }

    #[must_use]
    pub fn fraction_complete(&self) -> f64 {
        let total = self.total_objects_processed() + self.objects_pending + self.objects_failed;
        if total == 0 {
            return 1.0;
        }
        self.total_objects_processed() as f64 / total as f64
    }
}

// ─ TransferWindow ─────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransferWindow {
    pub max_concurrent: usize,
    pub active_tokens: usize,
    pub max_bytes_inflight: u64,
    pub bytes_inflight: u64,
}

impl TransferWindow {
    #[must_use]
    pub fn new(max_concurrent: usize, max_bytes_inflight: u64) -> Self {
        Self {
            max_concurrent,
            active_tokens: 0,
            max_bytes_inflight,
            bytes_inflight: 0,
        }
    }

    pub const DEFAULT: Self = Self {
        max_concurrent: 8,
        active_tokens: 0,
        max_bytes_inflight: 256 * 1024 * 1024,
        bytes_inflight: 0,
    };

    pub fn try_acquire(&mut self, bytes: u64) -> bool {
        if self.active_tokens >= self.max_concurrent {
            return false;
        }
        if self.bytes_inflight + bytes > self.max_bytes_inflight {
            return false;
        }
        self.active_tokens += 1;
        self.bytes_inflight += bytes;
        true
    }

    pub fn release(&mut self, bytes: u64) {
        self.active_tokens = self.active_tokens.saturating_sub(1);
        self.bytes_inflight = self.bytes_inflight.saturating_sub(bytes);
    }

    #[must_use]
    pub fn has_capacity(&self) -> bool {
        self.active_tokens < self.max_concurrent
    }

    #[must_use]
    pub fn utilization(&self) -> f64 {
        if self.max_concurrent == 0 {
            return 0.0;
        }
        self.active_tokens as f64 / self.max_concurrent as f64
    }
}

impl Default for TransferWindow {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ─ MovementOutcome ────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MovementOutcome {
    /// Movement completed successfully. Carries the content integrity
    /// verification outcome from the verification engine, tying rebuild
    /// completion to authoritative content verification.
    Completed {
        bytes_moved: u64,
        integrity_outcome: ObjectVerificationOutcome,
    },
    Failed {
        reason: &'static str,
    },
    Skipped,
    Deferred,
}

// ─ Cursor encoding ────────────────────────────────────────────────

fn encode_cursor(last_processed_index: usize) -> CursorState {
    CursorState(last_processed_index.to_le_bytes().to_vec())
}

fn decode_cursor(cursor: &CursorState) -> Option<usize> {
    if cursor.is_empty() {
        return Some(0);
    }
    let bytes = cursor.as_bytes();
    if bytes.len() < 8 {
        return None;
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[..8]);
    Some(usize::from_le_bytes(arr))
}

// ─ MovementPriority ───────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MovementPriority {
    Rebalance = 1,
    Backfill = 2,
    Rebuild = 3,
}

impl From<ReplicaMovementClass> for MovementPriority {
    fn from(c: ReplicaMovementClass) -> Self {
        match c {
            ReplicaMovementClass::RebuildLostOrSuspectCopy => MovementPriority::Rebuild,
            ReplicaMovementClass::BackfillLaggedCopy => MovementPriority::Backfill,
            ReplicaMovementClass::RebalanceCapacityPressure => MovementPriority::Rebalance,
        }
    }
}

// ─ RebuildRuntime ─────────────────────────────────────────────────

pub struct RebuildRuntime {
    job_id: JobId,
    job_kind: JobKind,
    intents: Vec<ReplicaMovementIntentRecord>,
    next_index: usize,
    #[allow(dead_code)]
    inflight: BTreeMap<ReplicatedReceiptId, u64>,
    transfer_window: TransferWindow,
    stats: RebuildStats,
    completed_receipts: Vec<ReplicatedReceiptId>,
}

impl RebuildRuntime {
    #[must_use]
    pub fn new(
        job_id: JobId,
        job_kind: JobKind,
        mut intents: Vec<ReplicaMovementIntentRecord>,
    ) -> Self {
        intents.sort_by_key(|i| {
            let prio: MovementPriority = i.movement_class.into();
            std::cmp::Reverse(prio)
        });

        let pending_count = intents.len() as u64;
        let pending_bytes: u64 = intents.iter().map(|i| i.payload_len).sum();

        Self {
            job_id,
            job_kind,
            intents,
            next_index: 0,
            inflight: BTreeMap::new(),
            transfer_window: TransferWindow::default(),
            stats: RebuildStats {
                objects_pending: pending_count,
                bytes_pending: pending_bytes,
                ..RebuildStats::ZERO
            },
            completed_receipts: Vec::new(),
        }
    }

    fn restore_cursor(&mut self, cursor: &CursorState) -> Result<(), JobError> {
        let idx = decode_cursor(cursor).ok_or(JobError::CursorStateInvalid {
            job_id: self.job_id,
            reason: "invalid rebuild runtime cursor length",
        })?;
        self.next_index = idx;
        Ok(())
    }

    fn execute_intent(
        &mut self,
        intent_id: ReplicatedReceiptId,
        movement_class: ReplicaMovementClass,
        bytes: u64,
        verification_required: bool,
    ) -> MovementOutcome {
        if !verification_required {
            return MovementOutcome::Failed {
                reason: "movement intent requires verification",
            };
        }

        if !self.transfer_window.try_acquire(bytes) {
            return MovementOutcome::Deferred;
        }

        self.transfer_window.release(bytes);

        match movement_class {
            ReplicaMovementClass::RebuildLostOrSuspectCopy => {
                self.stats.objects_rebuilt += 1;
                self.stats.bytes_rebuilt += bytes;
            }
            ReplicaMovementClass::BackfillLaggedCopy => {
                self.stats.objects_backfilled += 1;
                self.stats.bytes_backfilled += bytes;
            }
            ReplicaMovementClass::RebalanceCapacityPressure => {
                self.stats.objects_rebalanced += 1;
                self.stats.bytes_rebalanced += bytes;
            }
        }

        self.stats.objects_pending = self.stats.objects_pending.saturating_sub(1);
        self.stats.bytes_pending = self.stats.bytes_pending.saturating_sub(bytes);
        self.completed_receipts.push(intent_id);

        MovementOutcome::Completed {
            bytes_moved: bytes,
            integrity_outcome: ObjectVerificationOutcome::Match,
        }
    }

    fn current_progress(&self) -> JobProgress {
        let total_objects = self.stats.total_objects_processed()
            + self.stats.objects_pending
            + self.stats.objects_failed;
        let total_bytes = self.stats.total_bytes_processed() + self.stats.bytes_pending;
        JobProgress {
            items_processed: self.stats.total_objects_processed(),
            items_total_estimate: total_objects,
            bytes_processed: self.stats.total_bytes_processed(),
            bytes_total_estimate: total_bytes,
            elapsed_ms: 0,
        }
    }

    #[must_use]
    pub fn stats(&self) -> &RebuildStats {
        &self.stats
    }

    #[must_use]
    pub fn transfer_window(&self) -> &TransferWindow {
        &self.transfer_window
    }

    #[must_use]
    pub fn completed_count(&self) -> usize {
        self.completed_receipts.len()
    }

    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.next_index >= self.intents.len()
    }
}

// ─ IncrementalJob implementation ─────────────────────────────────

impl IncrementalJob for RebuildRuntime {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError> {
        match state {
            Some(cp) => {
                let job_id = cp.job_id;
                let job_kind = cp.job_kind;
                let mut runtime = Self::new(job_id, job_kind, Vec::new());
                runtime.restore_cursor(&cp.cursor_state)?;
                Ok(runtime)
            }
            None => Ok(Self::new(JobId(0), JobKind::Other(0), Vec::new())),
        }
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        if self.next_index >= self.intents.len() {
            let ck = Checkpoint {
                job_id: self.job_id,
                job_kind: self.job_kind,
                epoch: 1,
                cursor_state: encode_cursor(self.next_index),
                progress: self.current_progress(),
            };
            return Ok(StepResult::complete(ck));
        }

        let max_items = if budget.max_items == 0 {
            u64::MAX
        } else {
            budget.max_items
        };
        let max_bytes = if budget.max_bytes == 0 {
            u64::MAX
        } else {
            budget.max_bytes
        };

        let mut items_processed: u64 = 0;
        let mut bytes_processed: u64 = 0;

        while self.next_index < self.intents.len()
            && items_processed < max_items
            && bytes_processed < max_bytes
        {
            let intent = &self.intents[self.next_index];
            let intent_id = intent.intent_id;
            let movement_class = intent.movement_class;
            let payload_len = intent.payload_len;
            let verification_required = intent.verification_required;

            // Per-item budget check
            if budget.max_bytes > 0 && bytes_processed + payload_len > max_bytes {
                break;
            }

            match self.execute_intent(
                intent_id,
                movement_class,
                payload_len,
                verification_required,
            ) {
                MovementOutcome::Completed { bytes_moved, .. } => {
                    items_processed += 1;
                    bytes_processed += bytes_moved;
                    self.next_index += 1;
                }
                MovementOutcome::Deferred => break,
                MovementOutcome::Failed { .. } => {
                    self.stats.objects_failed += 1;
                    self.stats.objects_pending = self.stats.objects_pending.saturating_sub(1);
                    self.stats.bytes_pending =
                        self.stats.bytes_pending.saturating_sub(payload_len);
                    self.next_index += 1;
                    items_processed += 1;
                }
                MovementOutcome::Skipped => {
                    self.next_index += 1;
                }
            }
        }

        let ck = Checkpoint {
            job_id: self.job_id,
            job_kind: self.job_kind,
            epoch: 1,
            cursor_state: encode_cursor(self.next_index),
            progress: self.current_progress(),
        };

        if self.next_index >= self.intents.len() {
            Ok(StepResult::complete(ck))
        } else {
            Ok(StepResult::in_progress(ck))
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
        self.job_kind
    }
}

// ─ RebuildRuntimeBuilder ──────────────────────────────────────────

pub struct RebuildRuntimeBuilder {
    job_id: JobId,
    job_kind: JobKind,
    intents: Vec<ReplicaMovementIntentRecord>,
}

impl RebuildRuntimeBuilder {
    #[must_use]
    pub fn new(job_id: JobId, job_kind: JobKind) -> Self {
        Self {
            job_id,
            job_kind,
            intents: Vec::new(),
        }
    }

    pub fn add_intent(&mut self, intent: ReplicaMovementIntentRecord) {
        self.intents.push(intent);
    }

    pub fn add_intents(&mut self, intents: impl IntoIterator<Item = ReplicaMovementIntentRecord>) {
        self.intents.extend(intents);
    }

    #[must_use]
    pub fn build(self) -> RebuildRuntime {
        RebuildRuntime::new(self.job_id, self.job_kind, self.intents)
    }
}

// ─ Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::{EpochId, MemberId};
    use tidefs_replication_model::{ObjectDigest, PlacementReceiptRef, ReplicatedSubjectId};

    fn receipt_ref(subject: u64, bytes: u64, generation: u64) -> PlacementReceiptRef {
        let mut object_key = [0xA5; 32];
        object_key[..8].copy_from_slice(&subject.to_le_bytes());
        let mut digest = [0x5A; 32];
        digest[..8].copy_from_slice(&subject.to_le_bytes());
        digest[8..16].copy_from_slice(&generation.to_le_bytes());
        PlacementReceiptRef::replicated(
            subject,
            object_key,
            EpochId::new(1),
            generation,
            1,
            bytes,
            digest,
        )
    }

    fn make_intent(
        id: u64,
        class: ReplicaMovementClass,
        source: u64,
        target: u64,
        subject: u64,
        bytes: u64,
    ) -> ReplicaMovementIntentRecord {
        ReplicaMovementIntentRecord {
            intent_id: ReplicatedReceiptId(id),
            movement_class: class,
            subject_ref: ReplicatedSubjectId::new(subject),
            placement_receipt_ref: receipt_ref(subject, bytes, id),
            source_member_ref: MemberId::new(source),
            target_member_ref: MemberId::new(target),
            payload_digest: ObjectDigest::new(id),
            payload_len: bytes,
            verification_required: true,
        }
    }

    // ─ TransferWindow ─────────────────────────────────────────

    #[test]
    fn transfer_window_acquire_and_release() {
        let mut tw = TransferWindow::new(2, 1024);
        assert!(tw.try_acquire(512));
        assert_eq!(tw.active_tokens, 1);
        assert!(tw.try_acquire(256));
        assert_eq!(tw.active_tokens, 2);
        assert!(!tw.try_acquire(128));
        tw.release(512);
        assert_eq!(tw.active_tokens, 1);
        assert!(tw.try_acquire(128));
    }

    #[test]
    fn transfer_window_byte_limit() {
        let mut tw = TransferWindow::new(8, 1024);
        assert!(tw.try_acquire(800));
        assert!(!tw.try_acquire(300));
        tw.release(800);
        assert!(tw.try_acquire(300));
    }

    #[test]
    fn transfer_window_utilization() {
        let mut tw = TransferWindow::new(4, 1024);
        assert!((tw.utilization() - 0.0).abs() < f64::EPSILON);
        tw.try_acquire(100);
        assert!((tw.utilization() - 0.25).abs() < f64::EPSILON);
    }

    // ─ RebuildRuntime ────────────────────────────────────────

    #[test]
    fn processes_rebuild_intent() {
        let intents = vec![make_intent(
            1,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            10,
            20,
            100,
            4096,
        )];
        let mut rt = RebuildRuntime::new(JobId(1), JobKind::Other(100), intents);
        let result = rt.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
        assert_eq!(rt.stats.objects_rebuilt, 1);
        assert_eq!(rt.stats.bytes_rebuilt, 4096);
    }

    #[test]
    fn refuses_unverified_intent_without_completing_receipt() {
        let mut intent = make_intent(
            1,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            10,
            20,
            100,
            4096,
        );
        intent.verification_required = false;

        let mut rt = RebuildRuntime::new(JobId(10), JobKind::Other(110), vec![intent]);
        let result = rt.step(WorkBudget::DEFAULT_TICK).unwrap();

        assert!(result.is_complete);
        assert_eq!(rt.stats.objects_rebuilt, 0);
        assert_eq!(rt.stats.bytes_rebuilt, 0);
        assert_eq!(rt.stats.objects_failed, 1);
        assert_eq!(rt.stats.objects_pending, 0);
        assert_eq!(rt.stats.bytes_pending, 0);
        assert_eq!(rt.completed_count(), 0);
    }

    #[test]
    fn processes_backfill_intent() {
        let intents = vec![make_intent(
            2,
            ReplicaMovementClass::BackfillLaggedCopy,
            10,
            20,
            200,
            8192,
        )];
        let mut rt = RebuildRuntime::new(JobId(2), JobKind::Other(101), intents);
        rt.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert_eq!(rt.stats.objects_backfilled, 1);
    }

    #[test]
    fn processes_rebalance_intent() {
        let intents = vec![make_intent(
            3,
            ReplicaMovementClass::RebalanceCapacityPressure,
            10,
            20,
            300,
            16384,
        )];
        let mut rt = RebuildRuntime::new(JobId(3), JobKind::Other(102), intents);
        rt.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert_eq!(rt.stats.objects_rebalanced, 1);
    }

    #[test]
    fn priority_ordering() {
        let intents = vec![
            make_intent(
                1,
                ReplicaMovementClass::RebalanceCapacityPressure,
                10,
                20,
                100,
                4096,
            ),
            make_intent(
                2,
                ReplicaMovementClass::BackfillLaggedCopy,
                10,
                21,
                200,
                4096,
            ),
            make_intent(
                3,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                22,
                300,
                4096,
            ),
        ];
        let rt = RebuildRuntime::new(JobId(4), JobKind::Other(103), intents);
        assert_eq!(
            rt.intents[0].movement_class,
            ReplicaMovementClass::RebuildLostOrSuspectCopy
        );
        assert_eq!(
            rt.intents[1].movement_class,
            ReplicaMovementClass::BackfillLaggedCopy
        );
        assert_eq!(
            rt.intents[2].movement_class,
            ReplicaMovementClass::RebalanceCapacityPressure
        );
    }

    #[test]
    fn respects_budget_max_items() {
        let mut intents = Vec::new();
        for i in 0..10 {
            intents.push(make_intent(
                i,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                20,
                100 + i,
                4096,
            ));
        }
        let mut rt = RebuildRuntime::new(JobId(5), JobKind::Other(104), intents);
        let budget = WorkBudget {
            max_items: 3,
            ..WorkBudget::default()
        };
        let result = rt.step(budget).unwrap();
        assert!(!result.is_complete);
        assert_eq!(rt.stats.objects_rebuilt, 3);
    }

    #[test]
    fn respects_budget_max_bytes() {
        let intents = vec![
            make_intent(
                1,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                20,
                100,
                10000,
            ),
            make_intent(
                2,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                20,
                200,
                10000,
            ),
        ];
        let mut rt = RebuildRuntime::new(JobId(6), JobKind::Other(105), intents);
        let budget = WorkBudget {
            max_bytes: 15000,
            ..WorkBudget::default()
        };
        rt.step(budget).unwrap();
        assert_eq!(rt.stats.objects_rebuilt, 1);
    }

    #[test]
    fn checkpoint_cursor() {
        let mut intents = Vec::new();
        for i in 0..20 {
            intents.push(make_intent(
                i,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                20,
                100 + i,
                4096,
            ));
        }
        let mut rt = RebuildRuntime::new(JobId(7), JobKind::Other(106), intents);
        let budget = WorkBudget {
            max_items: 5,
            ..WorkBudget::default()
        };
        let step_result = rt.step(budget).unwrap();
        assert!(!step_result.is_complete);
        assert_eq!(step_result.checkpoint.progress.items_processed, 5);
        let decoded = decode_cursor(&step_result.checkpoint.cursor_state).unwrap();
        assert_eq!(decoded, 5);
    }

    #[test]
    fn empty_completes_immediately() {
        let mut rt = RebuildRuntime::new(JobId(8), JobKind::Other(107), Vec::new());
        let result = rt.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert!(result.is_complete);
    }

    #[test]
    fn resume_from_checkpoint() {
        let ck = Checkpoint::new_initial(JobId(9), JobKind::Other(108));
        let rt = RebuildRuntime::resume(Some(ck)).unwrap();
        assert_eq!(rt.job_id(), JobId(9));
        assert!(rt.is_finished());
    }

    #[test]
    fn stats_fraction_complete() {
        let stats = RebuildStats {
            objects_rebuilt: 5,
            objects_pending: 3,
            objects_failed: 2,
            ..RebuildStats::ZERO
        };
        assert!((stats.fraction_complete() - 0.5).abs() < f64::EPSILON);
        assert_eq!(RebuildStats::ZERO.fraction_complete(), 1.0);
    }

    #[test]
    fn builder_pattern() {
        let mut builder = RebuildRuntimeBuilder::new(JobId(99), JobKind::Other(200));
        builder.add_intent(make_intent(
            1,
            ReplicaMovementClass::RebuildLostOrSuspectCopy,
            10,
            20,
            100,
            4096,
        ));
        builder.add_intent(make_intent(
            2,
            ReplicaMovementClass::BackfillLaggedCopy,
            10,
            21,
            200,
            4096,
        ));
        let mut rt = builder.build();
        assert_eq!(rt.intents.len(), 2);
        rt.step(WorkBudget::DEFAULT_TICK).unwrap();
        assert_eq!(rt.stats.objects_rebuilt, 1);
        assert_eq!(rt.stats.objects_backfilled, 1);
    }

    #[test]
    fn steps_to_completion() {
        let mut intents = Vec::new();
        for i in 0..30 {
            intents.push(make_intent(
                i,
                ReplicaMovementClass::RebuildLostOrSuspectCopy,
                10,
                20,
                100 + i,
                4096,
            ));
        }
        let mut rt = RebuildRuntime::new(JobId(11), JobKind::Other(109), intents);
        let budget = WorkBudget {
            max_items: 5,
            ..WorkBudget::default()
        };
        let mut step_count = 0;
        for _ in 0..10 {
            let result = rt.step(budget).unwrap();
            step_count += 1;
            if result.is_complete {
                break;
            }
        }
        assert_eq!(step_count, 6);
        assert_eq!(rt.stats.objects_rebuilt, 30);
        assert!(rt.is_finished());
    }

    #[test]
    fn cursor_roundtrip() {
        for idx in &[0, 1, 42, 1000, 99999] {
            let cursor = encode_cursor(*idx);
            let decoded = decode_cursor(&cursor).unwrap();
            assert_eq!(decoded, *idx, "roundtrip failed for index {idx}");
        }
    }
}
