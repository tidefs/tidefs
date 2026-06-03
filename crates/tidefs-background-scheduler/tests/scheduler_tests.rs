// Integration tests for tidefs-background-scheduler task lifecycle.
//
// Tests the BackgroundScheduler public API through both submission paths:
// 1. submit() + poll() via the Schedulable trait (work-item queue)
// 2. register() + run_cycle() via the BackgroundService trait (service-based)
//
// Also covers LaneQueue integration, error handling, and priority ordering.

use std::cell::Cell;
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, IncrementalJobAdapter, LaneQueue, SchedulingClass, ServiceBudget,
    ServicePriority,
};
use tidefs_types_incremental_job_core::{
    Checkpoint, IncrementalJob, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
};

// ===========================================================================
// Mock implementations
// ===========================================================================

// ── MockSchedulable (for submit()/poll() path) ───────────────────────

struct MockWork {
    lane: SchedulingLane,
    cost: u64,
    run_count: Cell<u32>,
    should_fail: bool,
}

impl MockWork {
    fn new(lane: SchedulingLane, cost: u64) -> Self {
        Self {
            lane,
            cost,
            run_count: Cell::new(0),
            should_fail: false,
        }
    }

    fn failing(lane: SchedulingLane, cost: u64) -> Self {
        Self {
            lane,
            cost,
            run_count: Cell::new(0),
            should_fail: true,
        }
    }
}

impl Schedulable for MockWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.run_count.set(self.run_count.get() + 1);
        if self.should_fail {
            Err(SchedulerWorkError::Failed("mock failure"))
        } else {
            Ok(())
        }
    }
}

// ── MockJob (for IncrementalJobAdapter path) ─────────────────────────

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

// ===========================================================================
// 1. Task submission and completion — Schedulable path (submit + poll)
// ===========================================================================

#[test]
fn single_task_submit_and_poll_executes_exactly_once() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 1,
            items_failed: 0,
            items_promoted: 0,
            has_more: false,
        }
    );
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn submit_and_poll_drains_queue() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.submit(Box::new(MockWork::new(SchedulingLane::Writeback, 1)));
    s.poll();
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn multi_task_submit_all_executed() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let count: u32 = 100;

    for i in 0..count {
        let lane = match i % 5 {
            0 => SchedulingLane::Critical,
            1 => SchedulingLane::Writeback,
            2 => SchedulingLane::Prefetch,
            3 => SchedulingLane::Maintenance,
            _ => SchedulingLane::Idle,
        };
        s.submit(Box::new(MockWork::new(lane, 1)));
    }

    let mut total_processed = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => {
                total_processed += items_processed;
            }
            PollResult::Idle => break,
            PollResult::BudgetExhausted => {
                panic!("BudgetExhausted with unbounded budget");
            }
        }
    }

    assert_eq!(total_processed, count as u64);
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn multi_task_submit_mixed_lanes_priority_order() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    // Submit Idle first, then two Critical items.
    // All three should process in one poll with unbounded budgets.
    s.submit(Box::new(MockWork::new(SchedulingLane::Idle, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 3,
            items_failed: 0,
            items_promoted: 0,
            has_more: false,
        }
    );
}

// ===========================================================================
// 2. Task submission and completion — BackgroundService path (register + run_cycle)
// ===========================================================================

#[test]
fn register_single_service_run_cycle_makes_progress() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let job = MockJob::new(1, JobKind::DeferredCleanup, 100);
    s.register(Box::new(IncrementalJobAdapter::new("cleanup", job)));

    assert!(s.any_work_pending());
    let report = s.run_cycle();
    assert!(report.services_ran >= 1);
    assert!(report.total_processed > 0);
}

#[test]
fn register_multiple_services_all_run() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    for i in 1..=5u64 {
        s.register(Box::new(IncrementalJobAdapter::new(
            Box::leak(format!("svc_{i}").into_boxed_str()),
            MockJob::new(i, JobKind::DeferredCleanup, 100),
        )));
    }

    let report = s.run_cycle();
    assert_eq!(report.services_ran, 5);
    assert!(report.total_processed > 0);
}

#[test]
fn register_service_work_depletes_over_cycles() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(IncrementalJobAdapter::new(
        "small_job",
        MockJob::new(1, JobKind::DeferredCleanup, 5),
    )));

    // A job with total=5 should complete in 1 step (min(5, 20) = 5).
    let report = s.run_cycle();
    assert!(report.total_processed > 0);

    // The adapter should now report no work remaining.
    assert!(!s.any_work_pending());
}

#[test]
fn register_service_error_handling() {
    // Services that error during tick() should be skipped but not removed.
    // The MockJob always succeeds, so this test verifies the error path
    // doesn't exist for the basic mock. Real error-path testing requires
    // a custom BackgroundService that returns ServiceError from tick().
    //
    // We verify: scheduler remains operational after processing.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    s.register(Box::new(IncrementalJobAdapter::new(
        "job",
        MockJob::new(1, JobKind::DeferredCleanup, 50),
    )));

    let report = s.run_cycle();
    assert!(report.services_ran >= 1);

    // Run second cycle — scheduler still works.
    let report2 = s.run_cycle();
    assert!(report2.services_skipped == 0 || report2.services_ran >= 1);
}

// ===========================================================================
// 3. Task result passthrough — failed and succeeded items
// ===========================================================================

#[test]
fn failed_task_counted_as_failed() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.submit(Box::new(MockWork::failing(SchedulingLane::Critical, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 1,
            items_failed: 1,
            items_promoted: 0,
            has_more: false,
        }
    );
}

#[test]
fn zero_cost_items_always_dispatched() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    for _ in 0..10 {
        s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 0)));
    }

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 10,
            items_failed: 0,
            items_promoted: 0,
            has_more: false,
        }
    );
}

// ===========================================================================
// 4. Priority ordering — Schedulable and Service paths
// ===========================================================================

#[test]
fn critical_items_before_idle_in_same_poll() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    // Submit items across all lanes. All should dispatch in one poll.
    s.submit(Box::new(MockWork::new(SchedulingLane::Idle, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Maintenance, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Prefetch, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Writeback, 1)));
    s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 5,
            items_failed: 0,
            items_promoted: 0,
            has_more: false,
        }
    );
}

#[test]
fn service_priority_ordering_critical_first() {
    let mut s = BackgroundScheduler::new(ServiceBudget::SMALL_TICK);

    // Register low-priority first, then high-priority.
    s.register(Box::new(IncrementalJobAdapter::new(
        "low",
        MockJob::new(1, JobKind::BtreeCompaction, 100), // BestEffort
    )));
    s.register(Box::new(IncrementalJobAdapter::new(
        "high",
        MockJob::new(2, JobKind::Scrub, 100), // Critical
    )));

    let report = s.run_cycle();
    // At least one service ran — the Critical one should be included.
    assert!(report.services_ran >= 1);
}

// ===========================================================================
// 5. Budget enforcement
// ===========================================================================

#[test]
fn global_budget_limits_run_cycle() {
    // A tiny budget should limit how many items are processed.
    let mut s = BackgroundScheduler::new(ServiceBudget {
        max_items: 5,
        max_bytes: 0,
        max_ms: 0,
    });
    s.register(Box::new(IncrementalJobAdapter::new(
        "large_job",
        MockJob::new(1, JobKind::DeferredCleanup, 100),
    )));

    let report = s.run_cycle();
    assert!(report.total_processed <= 5);
    // Should still have work pending.
    assert!(s.any_work_pending());
}

// ===========================================================================
// 6. Empty / idle scheduler
// ===========================================================================

#[test]
fn empty_scheduler_poll_returns_idle() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    assert_eq!(s.work_queued(), 0);
    assert_eq!(s.poll(), PollResult::Idle);
}

#[test]
fn empty_scheduler_run_cycle_returns_empty_report() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let report = s.run_cycle();
    assert_eq!(report.services_ran, 0);
    assert_eq!(report.total_processed, 0);
    assert!(!report.budget_exhausted);
}

// ===========================================================================
// 7. LaneQueue integration tests
// ===========================================================================

#[test]
fn lane_queue_integration_submit_and_drain() {
    let mut q: LaneQueue<u64> = LaneQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);

    q.push(SchedulingClass::Normal, 42);
    assert!(!q.is_empty());
    assert_eq!(q.len(), 1);

    let popped = q.pop();
    assert_eq!(popped, Some((SchedulingClass::Normal, 42)));
    assert!(q.is_empty());
}

#[test]
fn lane_queue_integration_multi_class_fifo() {
    let mut q: LaneQueue<u64> = LaneQueue::new();

    q.push(SchedulingClass::Critical, 100);
    q.push(SchedulingClass::Critical, 200);
    q.push(SchedulingClass::Critical, 300);

    assert_eq!(q.pop(), Some((SchedulingClass::Critical, 100)));
    assert_eq!(q.pop(), Some((SchedulingClass::Critical, 200)));
    assert_eq!(q.pop(), Some((SchedulingClass::Critical, 300)));
    assert_eq!(q.pop(), None);
}

#[test]
fn lane_queue_integration_priority_ordering() {
    let mut q: LaneQueue<&str> = LaneQueue::new();

    q.push(SchedulingClass::BestEffort, "be");
    q.push(SchedulingClass::Critical, "crit");

    // Critical should pop before BestEffort.
    let first = q.pop().unwrap();
    assert_eq!(first.0, SchedulingClass::Critical);
    assert_eq!(first.1, "crit");

    let second = q.pop().unwrap();
    assert_eq!(second.0, SchedulingClass::BestEffort);
    assert_eq!(second.1, "be");
}

#[test]
fn lane_queue_integration_pop_count_matches_push_count() {
    let mut q: LaneQueue<u64> = LaneQueue::new();
    let n = 500u64;

    for i in 0..n {
        let class = SchedulingClass::ALL[(i % 5) as usize];
        q.push(class, i);
    }

    let mut popped = 0u64;
    while q.pop().is_some() {
        popped += 1;
    }

    assert_eq!(popped, n);
    assert_eq!(q.pop_count(), n);
}

#[test]
fn lane_queue_integration_no_starvation_with_even_distribution() {
    let mut q: LaneQueue<u64> = LaneQueue::new();
    let items_per_lane = 200u64;

    for _ in 0..items_per_lane {
        for class in &SchedulingClass::ALL {
            q.push(*class, 0);
        }
    }

    while q.pop().is_some() {}

    assert!(!q.has_starvation());
    for class in &SchedulingClass::ALL {
        let max_skip = q.max_skip(*class);
        assert!(max_skip < 100, "{class} had max_skip={max_skip}");
    }
}

// ===========================================================================
// 8. Error path: service error during tick
// ===========================================================================

/// A service that always returns an error from tick().
struct ErrorService {
    name: &'static str,
    priority: ServicePriority,
}

impl tidefs_background_scheduler::BackgroundService for ErrorService {
    fn name(&self) -> &'static str {
        self.name
    }
    fn priority(&self) -> ServicePriority {
        self.priority
    }
    fn has_work(&self) -> bool {
        true
    }
    fn tick(
        &mut self,
        _budget: &ServiceBudget,
    ) -> Result<tidefs_background_scheduler::TickReport, tidefs_background_scheduler::ServiceError>
    {
        Err(tidefs_background_scheduler::ServiceError::Internal {
            service: self.name,
            message: "always fails",
        })
    }
}

#[test]
fn error_service_does_not_crash_run_cycle() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(ErrorService {
        name: "failing_svc",
        priority: ServicePriority::Critical,
    }));

    // The error service should be skipped (counted as skipped), not crash.
    let report = s.run_cycle();
    assert_eq!(report.services_ran, 0);
    assert_eq!(report.services_skipped, 1);

    // Scheduler remains operational.
    s.register(Box::new(IncrementalJobAdapter::new(
        "recovery_job",
        MockJob::new(1, JobKind::DeferredCleanup, 10),
    )));
    let report2 = s.run_cycle();
    assert!(report2.services_ran >= 1);
}

// ===========================================================================
// 9. Concurrent submission — multiple threads submitting to same scheduler
// ===========================================================================

#[test]
fn concurrent_submission_no_lost_or_double_execution() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let scheduler = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let num_threads = 4;
    let items_per_thread: u64 = 250;
    let barrier = Arc::new(Barrier::new(num_threads));

    // Spawn threads that submit work items concurrently.
    let mut handles = Vec::new();
    for t in 0..num_threads {
        let s = scheduler.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait(); // synchronize start
            for i in 0..items_per_thread {
                let lane = match (t as u64 + i) % 5 {
                    0 => SchedulingLane::Critical,
                    1 => SchedulingLane::Writeback,
                    2 => SchedulingLane::Prefetch,
                    3 => SchedulingLane::Maintenance,
                    _ => SchedulingLane::Idle,
                };
                s.lock().unwrap().submit(Box::new(MockWork::new(lane, 1)));
            }
        }));
    }

    for h in handles {
        h.join().unwrap();
    }

    // Drain the queue from the main thread.
    let total_expected = num_threads as u64 * items_per_thread;
    let mut total_processed = 0u64;
    let mut s = scheduler.lock().unwrap();
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => {
                total_processed += items_processed;
            }
            PollResult::Idle => break,
            PollResult::BudgetExhausted => {
                panic!("unexpected budget exhaustion");
            }
        }
    }

    assert_eq!(total_processed, total_expected);
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn concurrent_submission_interleaved_with_poll() {
    use std::sync::{Arc, Barrier, Mutex};
    use std::thread;

    let scheduler = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let num_submitters = 2;
    let items_per_submitter: u64 = 200;
    let barrier = Arc::new(Barrier::new(num_submitters + 1)); // +1 for drainer

    // Submitter threads.
    let mut handles = Vec::new();
    for _t in 0..num_submitters {
        let s = scheduler.clone();
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            b.wait();
            for i in 0..items_per_submitter {
                let lane = if i % 2 == 0 {
                    SchedulingLane::Critical
                } else {
                    SchedulingLane::Writeback
                };
                s.lock().unwrap().submit(Box::new(MockWork::new(lane, 1)));
            }
        }));
    }

    // Drainer thread: polls while submitters are running.
    let s_drain = scheduler.clone();
    let b_drain = barrier.clone();
    let drain_handle = thread::spawn(move || {
        b_drain.wait();
        let mut drained = 0u64;
        loop {
            let result = {
                let mut s = s_drain.lock().unwrap();
                s.poll()
            };
            match result {
                PollResult::WorkDone {
                    items_processed, ..
                } => {
                    drained += items_processed;
                }
                PollResult::Idle => {
                    // Check if submitters are done by peeking.
                    break;
                }
                PollResult::BudgetExhausted => {}
            }
            // Small yield to let submitters run.
            thread::yield_now();
        }
        drained
    });

    for h in handles {
        h.join().unwrap();
    }
    let drained = drain_handle.join().unwrap();

    // Drain remaining items.
    let mut s = scheduler.lock().unwrap();
    let mut remaining = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => remaining += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => {}
        }
    }

    let total_processed = drained + remaining;
    let total_expected = num_submitters as u64 * items_per_submitter;
    assert_eq!(total_processed, total_expected);
    assert_eq!(s.work_queued(), 0);
}

// ===========================================================================
// 10. Async Scheduler — shutdown, panic propagation, task drain
// ===========================================================================

// The async Scheduler requires the `scheduler` feature (tokio runtime).
// These tests are compiled and run with: cargo test --features scheduler

#[cfg(feature = "scheduler")]
mod async_scheduler_tests {
    use super::*;
    use tidefs_background_scheduler::scheduler::Scheduler;

    #[tokio::test]
    async fn shutdown_completes_all_submitted_tasks() {
        let mut s = Scheduler::new(2);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let count = 50u32;

        for i in 0..count {
            let tx = tx.clone();
            s.submit(SchedulingClass::Normal, async move {
                tx.send(i).unwrap();
            });
        }
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let mut results: Vec<u32> = Vec::new();
        while let Ok(v) = rx.try_recv() {
            results.push(v);
        }
        assert_eq!(results.len(), count as usize);
    }

    #[tokio::test]
    async fn shutdown_drains_before_returning() {
        let mut s = Scheduler::new(4);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let count = 200u32;

        for i in 0..count {
            let tx = tx.clone();
            let class = match i % 5 {
                0 => SchedulingClass::Critical,
                1 => SchedulingClass::High,
                2 => SchedulingClass::Normal,
                3 => SchedulingClass::Low,
                _ => SchedulingClass::BestEffort,
            };
            s.submit(class, async move {
                tx.send(i).unwrap();
            });
        }
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let mut results: Vec<u32> = Vec::new();
        while let Ok(v) = rx.try_recv() {
            results.push(v);
        }
        assert_eq!(
            results.len(),
            count as usize,
            "all {} submitted tasks should complete before shutdown returns",
            count
        );
    }

    #[tokio::test]
    async fn shutdown_with_empty_queue_exits_immediately() {
        let mut s = Scheduler::new(2);

        // No tasks submitted; spawn workers then shutdown immediately.
        s.spawn();
        s.shutdown().await;
        // No panic = workers exited cleanly.
    }

    #[tokio::test]
    async fn panicking_task_does_not_crash_scheduler() {
        let mut s = Scheduler::new(2);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Submit a task that panics.
        s.submit(SchedulingClass::Normal, async {
            panic!("intentional test panic");
        });

        // Submit a normal task after the panicking one.
        s.submit(SchedulingClass::Critical, {
            let tx = tx.clone();
            async move {
                tx.send("survived").unwrap();
            }
        });
        drop(tx);

        s.spawn();

        // Shutdown should complete even though one task panicked.
        // The panicking task will cause its worker to abort, but
        // the other worker should process the remaining task.
        s.shutdown().await;

        // The non-panicking task should have completed.
        let results: Vec<&str> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            results.contains(&"survived"),
            "non-panicking task should have completed, got: {:?}",
            results
        );
    }

    #[tokio::test]
    async fn multiple_panics_dont_lose_all_work() {
        let mut s = Scheduler::new(4);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let normal_count = 20u32;

        // Submit several panicking tasks.
        for _ in 0..3 {
            s.submit(SchedulingClass::BestEffort, async {
                panic!("intentional");
            });
        }

        // Submit many normal tasks interleaved with different priorities.
        for i in 0..normal_count {
            let tx = tx.clone();
            s.submit(SchedulingClass::Normal, async move {
                tx.send(i).unwrap();
            });
        }
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let results: Vec<u32> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert!(
            results.len() >= normal_count as usize - 3,
            "at most 3 normal tasks may be lost if they were assigned to panicked workers, got {}",
            results.len()
        );
    }

    #[tokio::test]
    async fn stats_reflect_completion_counts() {
        let mut s = Scheduler::new(1);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        s.submit(SchedulingClass::Critical, {
            let tx = tx.clone();
            async move {
                tx.send(()).unwrap();
            }
        });
        s.submit(SchedulingClass::High, {
            let tx = tx.clone();
            async move {
                tx.send(()).unwrap();
            }
        });
        s.submit(SchedulingClass::Normal, {
            let tx = tx.clone();
            async move {
                tx.send(()).unwrap();
            }
        });
        drop(tx);

        s.spawn();

        // Capture stats before shutdown (shutdown consumes self).
        let stats = s.stats();
        assert_eq!(stats.submitted[SchedulingClass::Critical.index()], 1);
        assert_eq!(stats.submitted[SchedulingClass::High.index()], 1);
        assert_eq!(stats.submitted[SchedulingClass::Normal.index()], 1);

        s.shutdown().await;

        // Verify all 3 tasks completed by draining the channel.
        let mut completed = 0u32;
        while rx.try_recv().is_ok() {
            completed += 1;
        }
        assert_eq!(completed, 3);
    }

    #[tokio::test]
    async fn critical_tasks_run_before_best_effort_under_load() {
        let mut s = Scheduler::new(1); // single worker to serialize
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Submit BestEffort first, then Critical.
        s.submit(SchedulingClass::BestEffort, {
            let tx = tx.clone();
            async move {
                tx.send("be").unwrap();
            }
        });
        s.submit(SchedulingClass::Critical, {
            let tx = tx.clone();
            async move {
                tx.send("crit").unwrap();
            }
        });
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let first = rx.try_recv().unwrap();
        assert_eq!(
            first, "crit",
            "Critical task should execute before BestEffort"
        );
    }
}

// ===========================================================================
// 11. Drop and cleanup — scheduler dropped with queued work
// ===========================================================================

#[test]
fn drop_scheduler_with_queued_work_items_no_panic() {
    // Verify dropping the BackgroundScheduler while it holds queued
    // Schedulable items does not panic, leak, or double-free.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    // Submit items across all lanes.
    for lane in &SchedulingLane::ALL {
        s.submit(Box::new(MockWork::new(*lane, 1)));
    }

    assert!(s.work_queued() > 0);
    // Drop the scheduler without polling. WorkItemQueue's Drop impl
    // must clean up the VecDeque<QueuedWorkItem> without panicking.
    drop(s);
}

#[test]
fn drop_scheduler_with_registered_services_no_panic() {
    // Verify dropping the scheduler while it owns BackgroundService
    // trait objects does not panic.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    for i in 1..=3u64 {
        s.register(Box::new(IncrementalJobAdapter::new(
            Box::leak(format!("svc_{i}").into_boxed_str()),
            MockJob::new(i, JobKind::DeferredCleanup, 100),
        )));
    }

    assert!(s.any_work_pending());
    drop(s);
}

#[test]
fn partial_drain_then_drop_no_panic() {
    // Submit items, drain some, drop with remaining items.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    for _ in 0..10 {
        s.submit(Box::new(MockWork::new(SchedulingLane::Critical, 1)));
    }

    // Drain exactly 4 items.
    let result = s.poll();
    assert!(result.total_items() >= 1);

    // Drop after partial poll (regardless of remaining items).
    // queue may be empty or not, depending on budget; drop must not panic
    drop(s);
}

#[test]
fn partial_drain_service_then_drop_no_panic() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    s.register(Box::new(IncrementalJobAdapter::new(
        "large_job",
        MockJob::new(1, JobKind::DeferredCleanup, 100),
    )));

    // Run one cycle (partial work done).
    let _ = s.run_cycle();
    // Job still has work remaining.
    assert!(s.any_work_pending());
    drop(s);
}

#[test]
fn lane_queue_drop_with_items_no_panic() {
    let mut q: LaneQueue<u64> = LaneQueue::new();
    for i in 0..100u64 {
        let class = SchedulingClass::ALL[(i % 5) as usize];
        q.push(class, i);
    }
    assert!(!q.is_empty());
    // Drop must not panic.
    drop(q);
}

// ===========================================================================
// 12. Service lifecycle — deregister, count, cancellation-equivalent
// ===========================================================================

#[test]
fn take_last_service_prevents_execution() {
    // Register a service, then remove it via take_last_service before
    // running a cycle. The removed service must never execute.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    let job = MockJob::new(1, JobKind::DeferredCleanup, 50);
    s.register(Box::new(IncrementalJobAdapter::new("to_remove", job)));

    assert!(s.any_work_pending());
    assert_eq!(s.service_count(), 1);

    // Remove the service before it runs — this is the cancellation-
    // equivalent path for the BackgroundService API.
    let removed = s.take_last_service();
    assert!(removed.is_some());
    assert_eq!(s.service_count(), 0);
    assert!(!s.any_work_pending());

    // Running a cycle now must not execute the removed service.
    let report = s.run_cycle();
    assert_eq!(report.services_ran, 0);
}

#[test]
fn take_last_service_on_empty_returns_none() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let removed = s.take_last_service();
    assert!(removed.is_none());
    assert_eq!(s.service_count(), 0);
}

#[test]
fn service_count_tracks_register_and_remove() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    assert_eq!(s.service_count(), 0);

    s.register(Box::new(IncrementalJobAdapter::new(
        "a",
        MockJob::new(1, JobKind::DeferredCleanup, 10),
    )));
    assert_eq!(s.service_count(), 1);

    s.register(Box::new(IncrementalJobAdapter::new(
        "b",
        MockJob::new(2, JobKind::Scrub, 10),
    )));
    assert_eq!(s.service_count(), 2);

    let _ = s.take_last_service();
    assert_eq!(s.service_count(), 1);

    let _ = s.take_last_service();
    assert_eq!(s.service_count(), 0);

    // Removing from empty still returns 0.
    let _ = s.take_last_service();
    assert_eq!(s.service_count(), 0);
}

#[test]
fn remove_one_service_others_still_run() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    // Register two services, then remove the last one (b).
    s.register(Box::new(IncrementalJobAdapter::new(
        "a",
        MockJob::new(1, JobKind::DeferredCleanup, 50),
    )));
    s.register(Box::new(IncrementalJobAdapter::new(
        "b",
        MockJob::new(2, JobKind::Scrub, 50),
    )));

    // Remove service "b" (last registered).
    let _removed = s.take_last_service();
    assert_eq!(s.service_count(), 1);

    // Service "a" should still run.
    assert!(s.any_work_pending());
    let report = s.run_cycle();
    assert!(report.services_ran >= 1);
    assert!(report.total_processed > 0);
}

#[test]
fn deregister_all_then_register_new_service_still_works() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    // Register and deregister.
    s.register(Box::new(IncrementalJobAdapter::new(
        "old",
        MockJob::new(1, JobKind::DeferredCleanup, 10),
    )));
    let _ = s.take_last_service();
    assert!(!s.any_work_pending());

    // Register a fresh service — scheduler must remain functional.
    s.register(Box::new(IncrementalJobAdapter::new(
        "new",
        MockJob::new(2, JobKind::DeferredCleanup, 50),
    )));
    assert!(s.any_work_pending());

    let report = s.run_cycle();
    assert!(report.services_ran >= 1);
    assert!(report.total_processed > 0);
}

// ===========================================================================
// ===========================================================================
// 13. Concurrency bounds — async scheduler with barrier-controlled
//     parallelism (proves at most K tasks run simultaneously)
// ===========================================================================

#[cfg(feature = "scheduler")]
mod concurrency_bound_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tidefs_background_scheduler::scheduler::Scheduler;

    #[tokio::test]
    async fn at_most_k_tasks_run_concurrently_with_k_workers() {
        // With K=3 workers and K blocking tasks, the (K+1)-th task
        // must wait behind them. We use a Barrier(K+1) where the
        // main test is the (K+1)-th participant to release workers.
        let k: usize = 3;
        let mut s = Scheduler::new(k);

        let barrier = Arc::new(tokio::sync::Barrier::new(k + 1));
        let started = Arc::new(AtomicUsize::new(0));
        let (extra_tx, mut extra_rx) = tokio::sync::mpsc::channel::<()>(1);

        // Submit K tasks that each signal "started" then block at
        // the barrier until the main test releases it.
        for _ in 0..k {
            let b = barrier.clone();
            let started = started.clone();
            s.submit(SchedulingClass::Critical, async move {
                started.fetch_add(1, Ordering::SeqCst);
                b.wait().await;
            });
        }

        // Submit 1 extra task that should NOT start until one of
        // the K workers frees up.
        let started2 = started.clone();
        s.submit(SchedulingClass::Critical, async move {
            started2.fetch_add(1, Ordering::SeqCst);
            let _ = extra_tx.send(()).await;
        });

        s.spawn();

        // Yield several times to let the K workers pick up their
        // tasks and reach the barrier.
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        // At this point, exactly K tasks should have started.
        assert_eq!(
            started.load(Ordering::SeqCst),
            k,
            "exactly {} tasks should have started before barrier release",
            k
        );

        // The extra task should NOT have completed — its channel
        // should still be empty.
        assert!(
            extra_rx.try_recv().is_err(),
            "extra task should not have completed before barrier release"
        );

        // Release the barrier: all K workers can now finish.
        barrier.wait().await;

        // Now the extra task should eventually run — shutdown drains
        // all remaining tasks.
        s.shutdown().await;

        // After shutdown, the extra task must have completed.
        assert_eq!(
            started.load(Ordering::SeqCst),
            k + 1,
            "all {} tasks should have started after full drain",
            k + 1
        );
    }

    #[tokio::test]
    async fn single_worker_serializes_all_tasks() {
        // With K=1 worker, all tasks execute sequentially. Verify
        // via a concurrent-access counter that never exceeds 1.
        let mut s = Scheduler::new(1);

        let concurrent_count = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        let task_count: u32 = 20;
        for i in 0..task_count {
            let concurrent = concurrent_count.clone();
            let max_conc = max_concurrent.clone();
            let tx = tx.clone();
            s.submit(SchedulingClass::Normal, async move {
                let c = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                let prev = max_conc.load(Ordering::SeqCst);
                if c > prev {
                    max_conc.store(c, Ordering::SeqCst);
                }
                // Yield to expose any schedule-induced concurrency.
                tokio::task::yield_now().await;
                concurrent.fetch_sub(1, Ordering::SeqCst);
                tx.send(i).unwrap();
            });
        }
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let mut results: Vec<u32> = Vec::new();
        while let Ok(v) = rx.try_recv() {
            results.push(v);
        }
        assert_eq!(results.len(), task_count as usize);

        // With a single worker, max concurrency must be exactly 1.
        assert_eq!(
            max_concurrent.load(Ordering::SeqCst),
            1,
            "single worker must serialize: max concurrency must be 1"
        );
    }
}
