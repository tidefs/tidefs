//! Integration tests for tidefs-incremental-job-core (#4090).

use tidefs_incremental_job_core::{
    CheckpointCodec, CheckpointHeader, CheckpointHeaderError, DefaultCheckpointCodec,
    IncrementalJob, CHECKPOINT_HEADER_SIZE, CHECKPOINT_MAGIC, CHECKPOINT_MAX_PAYLOAD_SIZE,
    CHECKPOINT_VERSION,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JobState {
    Fresh,
    Running,
    Cancelled,
    Complete,
}

#[derive(Debug)]
struct StateTrackingJob {
    id: JobId,
    kind: JobKind,
    state: JobState,
    counter: u64,
    target: u64,
    last_checkpoint: std::cell::RefCell<Option<Checkpoint>>,
}

impl StateTrackingJob {
    fn encode_cursor(counter: u64) -> Vec<u8> {
        counter.to_le_bytes().to_vec()
    }

    fn decode_cursor(bytes: &[u8]) -> Option<u64> {
        if bytes.len() != 8 {
            return None;
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(bytes);
        Some(u64::from_le_bytes(arr))
    }

    fn is_cancelled(&self) -> bool {
        self.state == JobState::Cancelled
    }

    fn last_cp(&self) -> Option<Checkpoint> {
        self.last_checkpoint.borrow().clone()
    }

    fn set_last_cp(&self, cp: Checkpoint) {
        *self.last_checkpoint.borrow_mut() = Some(cp);
    }

    fn validate_monotonic(&self, new_cp: &Checkpoint) -> Result<(), JobError> {
        if let Some(ref last) = *self.last_checkpoint.borrow() {
            if new_cp.progress.items_processed < last.progress.items_processed {
                return Err(JobError::Other(
                    "checkpoint regression: items_processed went backwards".into(),
                ));
            }
            if new_cp.progress.items_processed == last.progress.items_processed
                && new_cp.epoch == last.epoch
            {
                return Err(JobError::Other(
                    "duplicate checkpoint: no progress made".into(),
                ));
            }
            if new_cp.epoch < last.epoch {
                return Err(JobError::Other("epoch regression detected".into()));
            }
        }
        Ok(())
    }
}

impl IncrementalJob for StateTrackingJob {
    fn resume(state: Option<Checkpoint>) -> Result<Self, JobError>
    where
        Self: Sized,
    {
        let cp = match state {
            Some(cp) => cp,
            None => {
                return Ok(StateTrackingJob {
                    id: JobId(1),
                    kind: JobKind::AdminJob,
                    state: JobState::Fresh,
                    counter: 0,
                    target: 100,
                    last_checkpoint: std::cell::RefCell::new(None),
                });
            }
        };

        let counter = if cp.cursor_state.is_empty() {
            if cp.progress.items_processed == 0 {
                return Ok(StateTrackingJob {
                    id: cp.job_id,
                    kind: cp.job_kind,
                    state: JobState::Fresh,
                    counter: 0,
                    target: 100,
                    last_checkpoint: std::cell::RefCell::new(Some(cp)),
                });
            }
            0
        } else {
            Self::decode_cursor(cp.cursor_state.as_bytes()).ok_or(JobError::CursorStateInvalid {
                job_id: cp.job_id,
                reason: "cursor must be 8 bytes or empty",
            })?
        };

        let state = if counter >= 100 {
            JobState::Complete
        } else {
            JobState::Running
        };

        Ok(StateTrackingJob {
            id: cp.job_id,
            kind: cp.job_kind,
            state,
            counter,
            target: 100,
            last_checkpoint: std::cell::RefCell::new(Some(cp)),
        })
    }

    fn step(&mut self, budget: WorkBudget) -> Result<StepResult, JobError> {
        match self.state {
            JobState::Complete => {
                return Err(JobError::JobAlreadyComplete { job_id: self.id });
            }
            JobState::Cancelled => {
                return Err(JobError::Other("job has been cancelled".into()));
            }
            JobState::Fresh | JobState::Running => {}
        }

        let max_items = if budget.max_items > 0 {
            budget.max_items
        } else {
            self.target - self.counter
        };

        let remaining = self.target - self.counter;
        let processed = max_items.min(remaining);
        self.counter += processed;
        self.state = JobState::Running;

        let is_complete = self.counter >= self.target;

        let checkpoint = Checkpoint {
            job_id: self.id,
            job_kind: self.kind,
            epoch: 1,
            cursor_state: CursorState(Self::encode_cursor(self.counter)),
            progress: JobProgress {
                items_processed: self.counter,
                items_total_estimate: self.target,
                bytes_processed: self.counter * 4096,
                bytes_total_estimate: self.target * 4096,
                elapsed_ms: self.counter,
            },
        };

        self.validate_monotonic(&checkpoint)?;

        if is_complete {
            self.state = JobState::Complete;
            Ok(StepResult::complete(checkpoint))
        } else {
            Ok(StepResult::in_progress(checkpoint))
        }
    }

    fn persist_checkpoint(&self, checkpoint: &Checkpoint) -> Result<(), JobError> {
        if let Some(ref last) = *self.last_checkpoint.borrow() {
            if checkpoint.progress.items_processed <= last.progress.items_processed {
                return Err(JobError::Other(
                    "persist rejected: checkpoint must advance".into(),
                ));
            }
        }
        self.set_last_cp(checkpoint.clone());
        Ok(())
    }

    fn complete(self) -> Result<(), JobError> {
        match self.state {
            JobState::Complete => Ok(()),
            JobState::Cancelled => Err(JobError::Other("cannot complete a cancelled job".into())),
            JobState::Fresh | JobState::Running => Ok(()),
        }
    }

    fn job_id(&self) -> JobId {
        self.id
    }

    fn job_kind(&self) -> JobKind {
        self.kind
    }
}

// ============================================================================
// 1. Lifecycle FSM
// ============================================================================

#[test]
fn lifecycle_fresh_to_running_to_complete() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    assert_eq!(job.state, JobState::Fresh);
    assert_eq!(job.job_id(), JobId(1));

    let r = job
        .step(WorkBudget {
            max_items: 30,
            ..WorkBudget::default()
        })
        .unwrap();
    assert!(!r.is_complete);
    assert_eq!(job.state, JobState::Running);

    let r = job
        .step(WorkBudget {
            max_items: 30,
            ..WorkBudget::default()
        })
        .unwrap();
    assert!(!r.is_complete);
    assert_eq!(job.state, JobState::Running);

    let r = job.step(WorkBudget::UNBOUNDED).unwrap();
    assert!(r.is_complete);
    assert_eq!(job.state, JobState::Complete);

    job.complete().unwrap();
}

#[test]
fn lifecycle_step_after_complete_errors() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    loop {
        let r = job.step(WorkBudget::UNBOUNDED).unwrap();
        if r.is_complete {
            break;
        }
    }
    assert_eq!(job.state, JobState::Complete);
    let err = job.step(WorkBudget::DEFAULT_TICK).unwrap_err();
    assert!(matches!(err, JobError::JobAlreadyComplete { .. }));
}

#[test]
fn lifecycle_complete_then_complete_again_idempotent() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let final_cp = loop {
        let r = job.step(WorkBudget::UNBOUNDED).unwrap();
        if r.is_complete {
            break r.checkpoint;
        }
    };
    job.complete().unwrap();

    let resumed = StateTrackingJob::resume(Some(final_cp)).unwrap();
    assert_eq!(resumed.state, JobState::Complete);
    resumed.complete().unwrap();
}

// ============================================================================
// 2. Resumption semantics
// ============================================================================

#[test]
fn resumption_through_codec_roundtrip() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let r1 = job
        .step(WorkBudget {
            max_items: 17,
            ..WorkBudget::default()
        })
        .unwrap();
    job.persist_checkpoint(&r1.checkpoint).unwrap();
    let r2 = job
        .step(WorkBudget {
            max_items: 23,
            ..WorkBudget::default()
        })
        .unwrap();
    job.persist_checkpoint(&r2.checkpoint).unwrap();
    assert_eq!(r2.checkpoint.progress.items_processed, 40);

    let encoded = DefaultCheckpointCodec::encode(&r2.checkpoint).unwrap();
    let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();

    let mut resumed = StateTrackingJob::resume(Some(decoded)).unwrap();
    assert_eq!(resumed.state, JobState::Running);
    assert_eq!(resumed.counter, 40);
    assert_eq!(resumed.job_id(), JobId(1));

    let r3 = resumed.step(WorkBudget::UNBOUNDED).unwrap();
    assert!(r3.is_complete);
    assert_eq!(r3.checkpoint.progress.items_processed, 100);
}

#[test]
fn resumption_empty_cursor_fresh_start() {
    let cp = Checkpoint {
        job_id: JobId(42),
        job_kind: JobKind::Scrub,
        epoch: 1,
        cursor_state: CursorState::empty(),
        progress: JobProgress::default(),
    };
    let job = StateTrackingJob::resume(Some(cp)).unwrap();
    assert_eq!(job.state, JobState::Fresh);
    assert_eq!(job.counter, 0);
    assert_eq!(job.job_id(), JobId(42));
}

#[test]
fn resumption_corrupt_cursor_errors() {
    let cp = Checkpoint {
        job_id: JobId(99),
        job_kind: JobKind::GCMark,
        epoch: 1,
        cursor_state: CursorState(vec![0xDE, 0xAD, 0xBE]),
        progress: JobProgress::default(),
    };
    let err = StateTrackingJob::resume(Some(cp)).unwrap_err();
    assert!(matches!(err, JobError::CursorStateInvalid { .. }));
}

// ============================================================================
// 3. Cancellation safety
// ============================================================================

#[test]
fn cancellation_rejects_further_steps() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let _ = job
        .step(WorkBudget {
            max_items: 20,
            ..WorkBudget::default()
        })
        .unwrap();

    job.state = JobState::Cancelled;
    assert!(job.is_cancelled());

    let err = job.step(WorkBudget::DEFAULT_TICK).unwrap_err();
    let err_msg = format!("{err}");
    assert!(err_msg.contains("cancelled"));
}

#[test]
fn cancellation_complete_is_rejected() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let _ = job
        .step(WorkBudget {
            max_items: 10,
            ..WorkBudget::default()
        })
        .unwrap();
    job.state = JobState::Cancelled;

    let err = job.complete().unwrap_err();
    assert!(format!("{err}").contains("cancelled"));
}

#[test]
fn cancellation_via_sentinel_cursor_detected() {
    let cancelled_cursor = u64::MAX.to_le_bytes().to_vec();
    let cp = Checkpoint {
        job_id: JobId(55),
        job_kind: JobKind::Rebake,
        epoch: 1,
        cursor_state: CursorState(cancelled_cursor),
        progress: JobProgress {
            items_processed: 30,
            ..Default::default()
        },
    };
    let resumed = StateTrackingJob::resume(Some(cp)).unwrap();
    assert_eq!(resumed.state, JobState::Complete);
    resumed.complete().unwrap();
}

// ============================================================================
// 4. Idempotent completion
// ============================================================================

#[test]
fn idempotent_completion_via_separate_instances() {
    let mut job1 = StateTrackingJob::resume(None).unwrap();
    let final_cp = loop {
        let r = job1.step(WorkBudget::UNBOUNDED).unwrap();
        if r.is_complete {
            break r.checkpoint;
        }
    };
    job1.complete().unwrap();

    let job2 = StateTrackingJob::resume(Some(final_cp.clone())).unwrap();
    assert_eq!(job2.state, JobState::Complete);
    job2.complete().unwrap();

    let mut job3 = StateTrackingJob::resume(Some(final_cp)).unwrap();
    assert_eq!(job3.state, JobState::Complete);
    let err = job3.step(WorkBudget::DEFAULT_TICK).unwrap_err();
    assert!(matches!(err, JobError::JobAlreadyComplete { .. }));
    job3.complete().unwrap();
}

#[test]
fn idempotent_completion_zero_remaining() {
    let cp = Checkpoint {
        job_id: JobId(8),
        job_kind: JobKind::BtreeCompaction,
        epoch: 1,
        cursor_state: CursorState(100u64.to_le_bytes().to_vec()),
        progress: JobProgress {
            items_processed: 100,
            items_total_estimate: 100,
            ..Default::default()
        },
    };
    let job = StateTrackingJob::resume(Some(cp)).unwrap();
    assert_eq!(job.state, JobState::Complete);
    job.complete().unwrap();
}

// ============================================================================
// 5. Checkpoint monotonicity
// ============================================================================

#[test]
fn monotonicity_accepts_increasing_checkpoints() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    for batch in &[10u64, 10, 10, 10, 10, 10, 10, 10, 10, 10] {
        let r = job
            .step(WorkBudget {
                max_items: *batch,
                ..WorkBudget::default()
            })
            .unwrap();
        job.persist_checkpoint(&r.checkpoint).unwrap();
        if r.is_complete {
            break;
        }
    }
    let last = job.last_cp().unwrap();
    assert_eq!(last.progress.items_processed, 100);
}

#[test]
fn monotonicity_rejects_regression() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let r = job
        .step(WorkBudget {
            max_items: 50,
            ..WorkBudget::default()
        })
        .unwrap();
    job.persist_checkpoint(&r.checkpoint).unwrap();

    let regressed_cp = Checkpoint {
        job_id: job.id,
        job_kind: job.kind,
        epoch: 1,
        cursor_state: CursorState(30u64.to_le_bytes().to_vec()),
        progress: JobProgress {
            items_processed: 30,
            items_total_estimate: 100,
            ..Default::default()
        },
    };
    let err = job.persist_checkpoint(&regressed_cp).unwrap_err();
    assert!(format!("{err}").contains("persist rejected"));
}

#[test]
fn monotonicity_rejects_duplicate_checkpoint() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let r = job
        .step(WorkBudget {
            max_items: 25,
            ..WorkBudget::default()
        })
        .unwrap();
    assert!(!r.is_complete);
    job.persist_checkpoint(&r.checkpoint).unwrap();

    let duplicate = Checkpoint {
        job_id: job.id,
        job_kind: job.kind,
        epoch: 1,
        cursor_state: CursorState(25u64.to_le_bytes().to_vec()),
        progress: JobProgress {
            items_processed: 25,
            items_total_estimate: 100,
            ..Default::default()
        },
    };
    let err = job.persist_checkpoint(&duplicate).unwrap_err();
    assert!(format!("{err}").contains("persist rejected"));
}

// ============================================================================
// 6. Budget edge cases
// ============================================================================

#[test]
fn budget_zero_items_processes_all_remaining() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let r = job.step(WorkBudget::UNBOUNDED).unwrap();
    assert!(r.is_complete);
}

#[test]
fn budget_single_item_per_step() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let mut step_count = 0u32;
    loop {
        let r = job
            .step(WorkBudget {
                max_items: 1,
                ..WorkBudget::default()
            })
            .unwrap();
        step_count += 1;
        if r.is_complete {
            break;
        }
    }
    assert_eq!(step_count, 100);
}

#[test]
fn budget_default_tick_batches() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let r = job.step(WorkBudget::DEFAULT_TICK).unwrap();
    assert!(r.is_complete);
}

// ============================================================================
// 7. Codec integration
// ============================================================================

#[test]
fn codec_roundtrip_preserves_all_fields() {
    let original = Checkpoint {
        job_id: JobId(0xDEAD_BEEF),
        job_kind: JobKind::OrphanRecovery,
        epoch: 42,
        cursor_state: CursorState(b"test-cursor-data-12345".to_vec()),
        progress: JobProgress {
            items_processed: 1_000_000,
            items_total_estimate: 5_000_000,
            bytes_processed: 4_000_000_000,
            bytes_total_estimate: 20_000_000_000,
            elapsed_ms: 99_999,
        },
    };
    let encoded = DefaultCheckpointCodec::encode(&original).unwrap();
    let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
    assert_eq!(decoded, original);
}

#[test]
fn codec_encode_exceeds_max_payload_errors() {
    let huge_cursor = vec![0u8; CHECKPOINT_MAX_PAYLOAD_SIZE];
    let cp = Checkpoint {
        job_id: JobId(1),
        job_kind: JobKind::AdminJob,
        epoch: 1,
        cursor_state: CursorState(huge_cursor),
        progress: JobProgress::default(),
    };
    let err = DefaultCheckpointCodec::encode(&cp).unwrap_err();
    assert!(matches!(err, JobError::Other(_)));
}

#[test]
fn codec_decode_unknown_version_rejected() {
    let mut buf = vec![0u8; CHECKPOINT_HEADER_SIZE + 61];
    CheckpointHeader {
        version: 99,
        payload_length: 61,
    }
    .write_to(&mut buf[..CHECKPOINT_HEADER_SIZE]);
    let err = DefaultCheckpointCodec::decode(&buf).unwrap_err();
    assert!(matches!(err, JobError::CheckpointCorrupt { .. }));
}

#[test]
fn codec_decode_unknown_kind_discriminant_reserved() {
    let mut buf = vec![0u8; CHECKPOINT_HEADER_SIZE + 61];
    CheckpointHeader {
        version: CHECKPOINT_VERSION,
        payload_length: 61,
    }
    .write_to(&mut buf[..CHECKPOINT_HEADER_SIZE]);
    buf[CHECKPOINT_HEADER_SIZE + 8] = 128;
    let err = DefaultCheckpointCodec::decode(&buf).unwrap_err();
    assert!(matches!(err, JobError::CheckpointCorrupt { .. }));
}

#[test]
fn codec_decode_truncated_cursor_state() {
    let mut buf = vec![0u8; CHECKPOINT_HEADER_SIZE + 66];
    CheckpointHeader {
        version: CHECKPOINT_VERSION,
        payload_length: 66,
    }
    .write_to(&mut buf[..CHECKPOINT_HEADER_SIZE]);
    buf[CHECKPOINT_HEADER_SIZE + 57] = 0xE8; // 1000 = 0x3E8
    buf[CHECKPOINT_HEADER_SIZE + 58] = 0x03;
    let err = DefaultCheckpointCodec::decode(&buf).unwrap_err();
    assert!(matches!(err, JobError::CheckpointCorrupt { .. }));
}

// ============================================================================
// 8. Magic and header checks
// ============================================================================

#[test]
fn checkpoint_magic_bytes_correct() {
    assert_eq!(CHECKPOINT_MAGIC, b"INCJCHKP");
}

#[test]
fn checkpoint_header_error_display() {
    let e1 = CheckpointHeaderError::UnsupportedVersion {
        found: 5,
        expected: 1,
    };
    assert!(format!("{e1}").contains("5"));
    let e2 = CheckpointHeaderError::PayloadTooLarge {
        found: 2_000_000,
        max: 1_048_576,
    };
    assert!(format!("{e2}").contains("2000000"));
}

// ============================================================================
// 9. JobKind discriminant coverage
// ============================================================================

#[test]
fn codec_all_job_kinds_survive_roundtrip() {
    let kinds = [
        JobKind::DeferredCleanup,
        JobKind::SnapshotDestroy,
        JobKind::GCMark,
        JobKind::BtreeCompaction,
        JobKind::Rebake,
        JobKind::JournalCleaning,
        JobKind::DatasetDestroy,
        JobKind::Scrub,
        JobKind::DeepScrub,
        JobKind::Resilver,
        JobKind::Recovery,
        JobKind::AdminJob,
        JobKind::Reclaim,
        JobKind::OrphanRecovery,
        JobKind::DerivedCatalog,
        JobKind::DataCleaner,
        JobKind::Defrag,
        JobKind::SegmentCleaner,
        JobKind::SnapshotPruner,
        JobKind::Dedup,
        JobKind::Rebuild,
        JobKind::Backfill,
        JobKind::Rebalance,
        JobKind::Other(42),
        JobKind::Other(127),
    ];
    for (i, &kind) in kinds.iter().enumerate() {
        let cp = Checkpoint {
            job_id: JobId(i as u64),
            job_kind: kind,
            epoch: 1,
            cursor_state: CursorState(vec![0x42]),
            progress: JobProgress {
                items_processed: i as u64,
                ..Default::default()
            },
        };
        let encoded = DefaultCheckpointCodec::encode(&cp).unwrap();
        let decoded = DefaultCheckpointCodec::decode(&encoded).unwrap();
        assert_eq!(decoded.job_kind, kind, "roundtrip failed for {kind:?}");
    }
}

// ============================================================================
// 10. Trait object and Send
// ============================================================================

#[test]
fn trait_object_dispatch_through_dyn() {
    let mut job = StateTrackingJob::resume(None).unwrap();
    let dyn_job: &mut dyn IncrementalJob = &mut job;
    assert_eq!(dyn_job.job_id(), JobId(1));
    assert_eq!(dyn_job.job_kind(), JobKind::AdminJob);
    let r = dyn_job
        .step(WorkBudget {
            max_items: 42,
            ..WorkBudget::default()
        })
        .unwrap();
    assert!(!r.is_complete);
    assert_eq!(r.checkpoint.progress.items_processed, 42);
}

#[test]
fn trait_box_dispatch() {
    let job = StateTrackingJob::resume(None).unwrap();
    let mut boxed: Box<dyn IncrementalJob> = Box::new(job);
    assert_eq!(boxed.job_id(), JobId(1));
    let r = boxed.step(WorkBudget::DEFAULT_TICK).unwrap();
    assert!(r.is_complete);
}

#[test]
fn trait_is_send_and_static() {
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<StateTrackingJob>();
}
