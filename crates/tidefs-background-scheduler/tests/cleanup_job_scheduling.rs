// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Integration tests: CleanupJob as BackgroundService in the scheduler.
// Covers: ticking in scheduler loop, budget enforcement, multi-service
// concurrent scheduling, and CleanupJobStats observability.

use tidefs_background_scheduler::{
    BackgroundScheduler, BackgroundService, IncrementalJobAdapter, ServiceBudget, ServicePriority,
};
use tidefs_cleanup_job_core::CleanupJob;
use tidefs_types_deferred_cleanup_core::{
    CleanupWorkItemV1, UnresolvedExtentMapRoot, WorkItemKind,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, IncrementalJob, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

// ── Helpers ───────────────────────────────────────────────────────────

fn make_item(inode_id: u64, kind: WorkItemKind, bytes: u64) -> CleanupWorkItemV1 {
    CleanupWorkItemV1::new(inode_id, kind, 1, UnresolvedExtentMapRoot::EMPTY, bytes)
}

fn make_items(count: u64) -> Vec<CleanupWorkItemV1> {
    (0..count)
        .map(|i| make_item(i, WorkItemKind::UnlinkFree, 4096 * (i + 1)))
        .collect()
}

// ── MockJob for multi-service tests ──────────────────────────────────

struct MockJob {
    id: JobId,
    kind: JobKind,
    total: u64,
    processed: u64,
}

impl MockJob {
    fn new(id: u64, kind: JobKind, total: u64) -> Self {
        Self {
            id: JobId(id),
            kind,
            total,
            processed: 0,
        }
    }
}

impl IncrementalJob for MockJob {
    fn resume(ck: Checkpoint) -> Result<Self, JobError> {
        let processed = if ck.cursor_state.is_empty() {
            0
        } else if ck.cursor_state.len() == 8 {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(ck.cursor_state.as_bytes());
            u64::from_le_bytes(buf)
        } else {
            return Err(JobError::CursorStateInvalid {
                job_id: ck.job_id,
                reason: "cursor must be 8 bytes",
            });
        };
        Ok(Self {
            id: ck.job_id,
            kind: ck.job_kind,
            total: 100,
            processed,
        })
    }

    fn step(&mut self, budget: WorkBudget) -> StepResult {
        let remaining = self.total - self.processed;
        let max = if budget.max_items == 0 {
            remaining
        } else {
            budget.max_items.min(remaining)
        };
        let batch = max.min(20);
        self.processed += batch;
        let progress = JobProgress {
            items_processed: batch,
            items_total_estimate: self.total,
            bytes_processed: batch * 1024,
            bytes_total_estimate: self.total * 1024,
            elapsed_ms: 5,
        };
        let ck = Checkpoint {
            job_id: self.id,
            job_kind: self.kind,
            epoch: 1,
            cursor_state: tidefs_types_incremental_job_core::CursorState(
                self.processed.to_le_bytes().to_vec(),
            ),
            progress,
        };
        if self.processed >= self.total {
            StepResult::complete(ck)
        } else {
            StepResult::in_progress(ck)
        }
    }

    fn persist_checkpoint(&self) -> Checkpoint {
        Checkpoint {
            job_id: self.id,
            job_kind: self.kind,
            epoch: 1,
            cursor_state: tidefs_types_incremental_job_core::CursorState(
                self.processed.to_le_bytes().to_vec(),
            ),
            progress: JobProgress {
                items_processed: self.processed,
                items_total_estimate: self.total,
                ..JobProgress::default()
            },
        }
    }

    fn complete(self) {}
    fn job_id(&self) -> JobId {
        self.id
    }
    fn job_kind(&self) -> JobKind {
        self.kind
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CleanupJob ticks in scheduler
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_job_ticks_in_scheduler_loop() {
    let items = make_items(50);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    let mut scheduler = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);
    scheduler.register(Box::new(adapter));

    let report = scheduler.run_cycle();
    assert!(report.services_ran >= 1, "cleanup service should run");
    assert!(report.total_processed > 0, "should process items");
}

#[test]
fn cleanup_job_has_throughput_priority() {
    let items = make_items(10);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    assert_eq!(adapter.priority(), ServicePriority::Throughput);
}

#[test]
fn cleanup_job_completes_in_scheduler() {
    let items = make_items(5);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    let mut scheduler = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    scheduler.register(Box::new(adapter));

    let mut cycles = 0u32;
    loop {
        let _report = scheduler.run_cycle();
        cycles += 1;
        if !scheduler.any_work_pending() {
            break;
        }
        if cycles > 20 {
            panic!("cleanup didn't complete in 20 cycles");
        }
    }
    assert!(cycles <= 5, "expected <=5 cycles, got {cycles}");
}

// ═══════════════════════════════════════════════════════════════════════
// Budget enforcement
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_job_respects_per_tick_budget() {
    let items = make_items(100);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    let tight_budget = ServiceBudget {
        max_items: 3,
        ..ServiceBudget::SMALL_TICK
    };

    let mut scheduler = BackgroundScheduler::new(tight_budget);
    scheduler.register(Box::new(adapter));

    let report = scheduler.run_cycle();
    assert!(
        report.total_processed + report.total_skipped + report.total_errors <= 3,
        "budget of 3 items should be respected, processed={}",
        report.total_processed
    );
    assert!(report.services_ran >= 1);
}
#[test]

fn cleanup_job_cursor_preserved_across_ticks() {
    let items = make_items(10);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    let tight_budget = ServiceBudget {
        max_items: 2,
        ..ServiceBudget::SMALL_TICK
    };

    let mut scheduler = BackgroundScheduler::new(tight_budget);
    scheduler.register(Box::new(adapter));

    let r1 = scheduler.run_cycle();
    assert!(r1.total_processed >= 2, "should process at least 2 items");
    assert!(
        scheduler.any_work_pending(),
        "more items should remain after first cycle"
    );

    let r2 = scheduler.run_cycle();
    assert!(
        r2.total_processed >= 2,
        "should process more items in second cycle"
    );
    assert!(
        scheduler.any_work_pending(),
        "more items remain after 2 cycles"
    );
}
// ═══════════════════════════════════════════════════════════════════════
// Multi-service concurrent scheduling
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_runs_alongside_other_services() {
    let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);

    let cleanup = CleanupJob::new(make_items(20));
    scheduler.register(Box::new(IncrementalJobAdapter::new("cleanup", cleanup)));

    let scrub = MockJob::new(1, JobKind::Scrub, 50);
    scheduler.register(Box::new(IncrementalJobAdapter::new("scrub", scrub)));

    let compaction = MockJob::new(2, JobKind::BtreeCompaction, 30);
    scheduler.register(Box::new(IncrementalJobAdapter::new(
        "compaction",
        compaction,
    )));

    let report = scheduler.run_cycle();
    assert!(
        report.services_ran >= 3,
        "all 3 services should run, ran={}",
        report.services_ran
    );
}

#[test]
fn cleanup_priority_respected_with_critical_service() {
    let mut scheduler = BackgroundScheduler::new(ServiceBudget {
        max_items: 5,
        ..ServiceBudget::DEFAULT_TICK
    });

    let cleanup = CleanupJob::new(make_items(100));
    scheduler.register(Box::new(IncrementalJobAdapter::new("cleanup", cleanup)));

    let crit = MockJob::new(1, JobKind::Scrub, 5);
    scheduler.register(Box::new(IncrementalJobAdapter::new("scrub", crit)));

    let report = scheduler.run_cycle();
    assert!(
        report.services_ran >= 2,
        "both services should run with budget cascade, ran={}",
        report.services_ran
    );
}

// ═══════════════════════════════════════════════════════════════════════
// Stats observability
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_has_work_initially() {
    let items = make_items(10);
    let job = CleanupJob::new(items);
    let mut adapter = IncrementalJobAdapter::new("cleanup", job);

    assert!(adapter.has_work());

    let budget = ServiceBudget {
        max_items: 5,
        ..ServiceBudget::DEFAULT_TICK
    };
    let report = adapter.tick(&budget).unwrap();
    assert!(report.processed > 0);
    assert!(report.has_more);
}

#[test]
fn cleanup_idle_when_no_items() {
    let job = CleanupJob::new(Vec::new());
    let mut adapter = IncrementalJobAdapter::new("cleanup", job);
    // Empty job needs one tick to register as complete.
    let budget = ServiceBudget::SMALL_TICK;
    let report = adapter.tick(&budget).unwrap();
    assert!(!report.has_more);
    assert!(!adapter.has_work());
}

#[test]
fn cleanup_name_and_priority_preserved() {
    let job = CleanupJob::new(make_items(10));
    let adapter = IncrementalJobAdapter::new("deferred_cleanup", job);

    assert_eq!(adapter.name(), "deferred_cleanup");
    assert_eq!(adapter.priority(), ServicePriority::Throughput);
}

// ═══════════════════════════════════════════════════════════════════════
// Throughput measurement
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_throughput_across_cycles() {
    let items = make_items(100);
    let job = CleanupJob::new(items);
    let adapter = IncrementalJobAdapter::new("cleanup", job);

    let mut scheduler = BackgroundScheduler::new(ServiceBudget::DEFAULT_TICK);
    scheduler.register(Box::new(adapter));

    let mut total = 0u64;
    let mut cycles = 0u32;

    while scheduler.any_work_pending() {
        let report = scheduler.run_cycle();
        total += report.total_processed;
        cycles += 1;
        if cycles > 50 {
            break;
        }
    }

    assert_eq!(total, 100, "all items should be processed, got {total}");
    assert!(cycles <= 5, "should complete in few cycles, got {cycles}");
}

// ═══════════════════════════════════════════════════════════════════════
// Service count
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn multiple_cleanup_services_counted() {
    let mut scheduler = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);

    scheduler.register(Box::new(IncrementalJobAdapter::new(
        "cleanup_a",
        CleanupJob::new(make_items(5)),
    )));
    scheduler.register(Box::new(IncrementalJobAdapter::new(
        "cleanup_b",
        CleanupJob::new(make_items(5)),
    )));

    assert_eq!(scheduler.service_count(), 2);
}

// ═══════════════════════════════════════════════════════════════════════
// Idle after completion
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn cleanup_idle_after_completion() {
    let job = CleanupJob::new(make_items(3));
    let mut adapter = IncrementalJobAdapter::new("cleanup", job);

    let budget = ServiceBudget::UNBOUNDED;
    let report = adapter.tick(&budget).unwrap();
    assert!(!report.has_more, "should be complete after unbounded tick");
    assert!(!adapter.has_work());
}
