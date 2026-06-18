// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Shutdown and lifecycle edge-case tests for tidefs-background-scheduler.
//
// Covers: drop safety with pending work, service removal/re-registration,
// LaneQueue starvation edge cases, and idle detection correctness.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, IncrementalJobAdapter, LaneQueue, SchedulingClass, ServiceBudget,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, CursorState, IncrementalJob, JobError, JobId, JobKind, JobProgress, StepResult,
    WorkBudget,
};

// ── CountingWork ──────────────────────────────────────────────────────

struct CountingWork {
    lane: SchedulingLane,
    cost: u64,
    counter: Arc<AtomicUsize>,
}

impl CountingWork {
    fn new(lane: SchedulingLane, cost: u64, counter: Arc<AtomicUsize>) -> Self {
        Self {
            lane,
            cost,
            counter,
        }
    }
}

impl Schedulable for CountingWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// ── DummyJob ──────────────────────────────────────────────────────────

struct DummyJob {
    id: JobId,
    kind: JobKind,
    total: u64,
    processed: u64,
}

impl DummyJob {
    fn new(id: u64, kind: JobKind, total: u64) -> Self {
        Self {
            id: JobId(id),
            kind,
            total,
            processed: 0,
        }
    }
}

impl IncrementalJob for DummyJob {
    fn resume(ck: Checkpoint) -> Result<Self, JobError> {
        let processed = if ck.cursor_state.is_empty() {
            0
        } else {
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&ck.cursor_state.as_bytes()[..8]);
            u64::from_le_bytes(buf)
        };
        Ok(Self {
            id: ck.job_id,
            kind: ck.job_kind,
            total: 100,
            processed,
        })
    }
    fn step(&mut self, _budget: WorkBudget) -> StepResult {
        let batch = 1;
        self.processed += batch;
        let ck = Checkpoint {
            job_id: self.id,
            job_kind: self.kind,
            epoch: 1,
            cursor_state: CursorState(self.processed.to_le_bytes().to_vec()),
            progress: JobProgress {
                items_processed: batch,
                ..JobProgress::default()
            },
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
            cursor_state: CursorState(self.processed.to_le_bytes().to_vec()),
            progress: JobProgress {
                items_processed: self.processed,
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

// ── Drop safety ───────────────────────────────────────────────────────

#[test]
fn drop_with_pending_work_no_panic() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    for _ in 0..50 {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            counter.clone(),
        )));
    }
    // Dropped here; boxed trait objects cleaned up via Vec drop.
}

#[test]
fn drop_with_registered_services_no_panic() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(IncrementalJobAdapter::new(
        "j1",
        DummyJob::new(1, JobKind::DeferredCleanup, 100),
    )));
    s.register(Box::new(IncrementalJobAdapter::new(
        "j2",
        DummyJob::new(2, JobKind::GCMark, 50),
    )));
    // Dropped without running.
}

#[test]
fn drop_after_partial_drain_no_panic() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    for _ in 0..20 {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            counter.clone(),
        )));
    }
    s.poll();
    assert!(counter.load(Ordering::SeqCst) > 0);
    // Drop remaining.
}

// ── Service lifecycle ─────────────────────────────────────────────────

#[test]
fn take_last_service_removes_from_scheduler() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(IncrementalJobAdapter::new(
        "rem",
        DummyJob::new(1, JobKind::DeferredCleanup, 10),
    )));
    assert_eq!(s.service_count(), 1);
    let removed = s.take_last_service();
    assert!(removed.is_some());
    assert_eq!(s.service_count(), 0);
    // Running cycle with no services is safe.
    let report = s.run_cycle();
    assert_eq!(report.services_ran, 0);
}

#[test]
fn re_register_after_full_removal() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(IncrementalJobAdapter::new(
        "first",
        DummyJob::new(1, JobKind::DeferredCleanup, 1),
    )));
    let _ = s.take_last_service();
    assert_eq!(s.service_count(), 0);
    s.register(Box::new(IncrementalJobAdapter::new(
        "second",
        DummyJob::new(2, JobKind::GCMark, 1),
    )));
    assert_eq!(s.service_count(), 1);
    let report = s.run_cycle();
    assert!(report.services_ran >= 1);
}

// ── Idle detection ────────────────────────────────────────────────────

#[test]
fn poll_returns_idle_on_empty_scheduler() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    assert_eq!(s.poll(), PollResult::Idle);
    assert_eq!(s.poll(), PollResult::Idle);
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn run_cycle_empty_returns_zero_services() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let report = s.run_cycle();
    assert_eq!(report.services_ran, 0);
    assert_eq!(report.services_skipped, 0);
}

#[test]
fn submit_after_poll_idle_continues_working() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    // Batch 1.
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    s.poll();
    assert_eq!(s.poll(), PollResult::Idle);
    // Batch 2 after idle.
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    s.poll();
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn mixed_lanes_after_previous_drain() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    for _ in 0..5 {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            counter.clone(),
        )));
    }
    while s.poll() != PollResult::Idle {}
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Idle,
        1,
        counter.clone(),
    )));
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    while s.poll() != PollResult::Idle {}
    assert_eq!(counter.load(Ordering::SeqCst), 7);
}

// ── LaneQueue edge cases ──────────────────────────────────────────────

#[test]
fn lane_queue_default_no_starvation() {
    let q: LaneQueue<u32> = LaneQueue::new();
    assert!(!q.has_starvation());
    assert_eq!(q.pop_count(), 0);
}

#[test]
fn lane_queue_max_skip_zero_for_idle_lanes() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    for i in 0..10 {
        q.push(SchedulingClass::Critical, i);
    }
    while q.pop().is_some() {}
    assert_eq!(q.max_skip(SchedulingClass::BestEffort), 0);
    assert_eq!(q.max_skip(SchedulingClass::Low), 0);
}

#[test]
fn lane_queue_starvation_serves_low_priority_within_threshold() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    q.push(SchedulingClass::BestEffort, 999);
    for i in 0..300 {
        q.push(SchedulingClass::Critical, 1000 + i);
    }
    let mut found = false;
    let mut pops = 0;
    while let Some((class, val)) = q.pop() {
        pops += 1;
        if class == SchedulingClass::BestEffort {
            assert_eq!(val, 999);
            found = true;
            break;
        }
        if pops > 200 {
            break;
        }
    }
    assert!(
        found,
        "BestEffort should be served via starvation prevention"
    );
}

// ── Service count and removal ─────────────────────────────────────────

#[test]
fn service_count_zero_after_removing_only_service() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    assert_eq!(s.service_count(), 0);
    s.register(Box::new(IncrementalJobAdapter::new(
        "only",
        DummyJob::new(1, JobKind::DeferredCleanup, 10),
    )));
    assert_eq!(s.service_count(), 1);
    let _ = s.take_last_service();
    assert_eq!(s.service_count(), 0);
}

#[test]
fn take_last_service_on_empty_returns_none() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    assert!(s.take_last_service().is_none());
}
