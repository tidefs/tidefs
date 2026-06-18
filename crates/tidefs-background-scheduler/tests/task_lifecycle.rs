// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Task lifecycle tests for tidefs-background-scheduler.
//
// Covers task submission, execution, result propagation, error recovery,
// completion tracking, and lifecycle edge cases through the
// BackgroundScheduler submit/poll path (Schedulable trait).

// use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, ServiceBudget,
};

// =========================================================================
// Mock Schedulable implementations
// =========================================================================

/// A work item that records its execution via a shared counter.
struct CountingWork {
    lane: SchedulingLane,
    cost: u64,
    run_count: Arc<AtomicUsize>,
    should_fail: bool,
}

impl CountingWork {
    fn new(lane: SchedulingLane, cost: u64, counter: Arc<AtomicUsize>) -> Self {
        Self {
            lane,
            cost,
            run_count: counter,
            should_fail: false,
        }
    }

    fn failing(lane: SchedulingLane, cost: u64, counter: Arc<AtomicUsize>) -> Self {
        Self {
            lane,
            cost,
            run_count: counter,
            should_fail: true,
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
        self.run_count.fetch_add(1, Ordering::SeqCst);
        if self.should_fail {
            Err(SchedulerWorkError::Failed("counting-work failure"))
        } else {
            Ok(())
        }
    }
}

/// A work item that records the order in which it was executed.
struct OrderedWork {
    lane: SchedulingLane,
    cost: u64,
    id: u64,
    order_log: Arc<std::sync::Mutex<Vec<u64>>>,
}

impl OrderedWork {
    fn new(lane: SchedulingLane, cost: u64, id: u64, log: Arc<std::sync::Mutex<Vec<u64>>>) -> Self {
        Self {
            lane,
            cost,
            id,
            order_log: log,
        }
    }
}

impl Schedulable for OrderedWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }

    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.order_log.lock().unwrap().push(self.id);
        Ok(())
    }
}

/// A work item that signals completion via a flag.
struct SignalWork {
    lane: SchedulingLane,
    cost: u64,
    done: Arc<AtomicBool>,
}

impl SignalWork {
    fn new(lane: SchedulingLane, cost: u64, done: Arc<AtomicBool>) -> Self {
        Self { lane, cost, done }
    }
}

impl Schedulable for SignalWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }

    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.done.store(true, Ordering::SeqCst);
        Ok(())
    }
}

// =========================================================================
// Task submission and lifecycle
// =========================================================================

#[test]
fn submit_noop_task_executes_and_marks_complete() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));

    let result = s.poll();
    assert_eq!(
        result,
        PollResult::WorkDone {
            items_processed: 1,
            items_failed: 0,
            items_promoted: 0,
            has_more: false
        }
    );
    assert_eq!(counter.load(Ordering::SeqCst), 1);
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn submit_multiple_tasks_all_execute() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    let n = 10;

    for _ in 0..n {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            counter.clone(),
        )));
    }

    let mut total = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected budget exhaustion"),
        }
    }

    assert_eq!(total, n);
    assert_eq!(counter.load(Ordering::SeqCst), n as usize);
}

// =========================================================================
// Result propagation via side effects
// =========================================================================

#[test]
fn result_propagation_via_shared_state() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let done = Arc::new(AtomicBool::new(false));

    s.submit(Box::new(SignalWork::new(
        SchedulingLane::Critical,
        1,
        done.clone(),
    )));

    // Before poll, not done.
    assert!(!done.load(Ordering::SeqCst));
    s.poll();
    assert!(done.load(Ordering::SeqCst));
}

#[test]
fn result_propagation_multiple_outputs() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let order = Arc::new(std::sync::Mutex::new(Vec::new()));

    s.submit(Box::new(OrderedWork::new(
        SchedulingLane::Critical,
        1,
        1,
        order.clone(),
    )));
    s.submit(Box::new(OrderedWork::new(
        SchedulingLane::Critical,
        1,
        2,
        order.clone(),
    )));
    s.submit(Box::new(OrderedWork::new(
        SchedulingLane::Critical,
        1,
        3,
        order.clone(),
    )));

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected budget exhaustion"),
        }
    }

    let executed = order.lock().unwrap();
    assert_eq!(executed.len(), 3);
    // All three IDs should be present, FIFO order within same lane.
    assert!(executed.contains(&1));
    assert!(executed.contains(&2));
    assert!(executed.contains(&3));
    assert_eq!(*executed, vec![1, 2, 3]);
}

// =========================================================================
// Error recovery: failed tasks don't crash the scheduler
// =========================================================================

#[test]
fn failed_task_counted_and_scheduler_continues() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));

    // Submit a failing task first, then a good task.
    s.submit(Box::new(CountingWork::failing(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));

    // Both items are drained in a single poll call with unbounded budgets.
    let r = s.poll();
    assert_eq!(
        r,
        PollResult::WorkDone {
            items_processed: 1,
            items_failed: 1,
            items_promoted: 0,
            has_more: false
        }
    );

    // Both tasks were attempted (the good one executed, the failing one tried).
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

#[test]
fn multiple_failures_do_not_block_good_tasks() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));

    // Interleave failing and good tasks.
    for i in 0..10 {
        if i % 2 == 0 {
            s.submit(Box::new(CountingWork::failing(
                SchedulingLane::Critical,
                1,
                counter.clone(),
            )));
        } else {
            s.submit(Box::new(CountingWork::new(
                SchedulingLane::Critical,
                1,
                counter.clone(),
            )));
        }
    }

    let mut processed = 0u64;
    let mut failed = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed,
                items_failed,
                ..
            } => {
                processed += items_processed;
                failed += items_failed;
            }
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected budget exhaustion"),
        }
    }

    assert_eq!(processed, 5);
    assert_eq!(failed, 5);
    assert_eq!(counter.load(Ordering::SeqCst), 10);
}

// =========================================================================
// Task completion tracking
// =========================================================================

#[test]
fn completion_tracks_each_individual_task() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let n: u64 = 50;

    for i in 0..n {
        let lane = match i % 5 {
            0 => SchedulingLane::Critical,
            1 => SchedulingLane::Writeback,
            2 => SchedulingLane::Prefetch,
            3 => SchedulingLane::Maintenance,
            _ => SchedulingLane::Idle,
        };
        s.submit(Box::new(CountingWork::new(
            lane,
            1,
            Arc::new(AtomicUsize::new(0)),
        )));
    }

    let mut total = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected budget exhaustion"),
        }
    }

    assert_eq!(total, n);
    assert_eq!(s.work_queued(), 0);
}

// =========================================================================
// Empty scheduler edge cases
// =========================================================================

#[test]
fn empty_scheduler_submit_and_drain() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    assert_eq!(s.poll(), PollResult::Idle);
    assert_eq!(s.work_queued(), 0);
}

#[test]
fn submit_then_idle_then_submit_again() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));

    // First batch.
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    s.poll();
    assert_eq!(s.poll(), PollResult::Idle);

    // Second batch.
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter.clone(),
    )));
    s.poll();

    assert_eq!(counter.load(Ordering::SeqCst), 2);
    assert_eq!(s.poll(), PollResult::Idle);
}

// =========================================================================
// Budget and drain behavior
// =========================================================================

#[test]
fn unbounded_budget_drains_all() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);

    for _ in 0..50 {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            Arc::new(AtomicUsize::new(0)),
        )));
    }

    let mut total = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unbounded budget should not exhaust"),
        }
    }

    assert_eq!(total, 50);
}

// =========================================================================
// Drop safety: dropped scheduler with queued work must not panic
// =========================================================================

#[test]
fn drop_scheduler_with_pending_work_no_panic() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let counter = Arc::new(AtomicUsize::new(0));
    s.submit(Box::new(CountingWork::new(
        SchedulingLane::Critical,
        1,
        counter,
    )));
    // s dropped here — must not panic.
}

#[test]
fn partial_drain_then_drop_no_panic() {
    let budget = ServiceBudget {
        max_items: 2,
        max_bytes: 0,
        max_ms: 0,
    };
    let mut s = BackgroundScheduler::new(budget);
    let counter = Arc::new(AtomicUsize::new(0));

    for _ in 0..10 {
        s.submit(Box::new(CountingWork::new(
            SchedulingLane::Critical,
            1,
            counter.clone(),
        )));
    }

    // Drain only part of the queue.
    s.poll();
    // Remaining items are dropped with the scheduler.
}
