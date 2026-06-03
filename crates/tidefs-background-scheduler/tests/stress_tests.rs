// Randomized stress and timing-sensitive tests for tidefs-background-scheduler.
//
// Covers: high-volume task submission (10K+), randomized priority ordering
// verification, slow-task non-blocking behavior, burst-submission timing,
// and starvation-freedom under adversarial lane weighting.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use std::time::{Duration, Instant};
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, LaneQueue, SchedulingClass, ServiceBudget,
};

// =========================================================================
// CountingWork with ID tracking (for verifying no lost/double items)
// =========================================================================

struct IdCountingWork {
    lane: SchedulingLane,
    cost: u64,
    id: u64,
    executed_ids: Arc<Mutex<Vec<u64>>>,
}

impl IdCountingWork {
    fn new(lane: SchedulingLane, cost: u64, id: u64, executed_ids: Arc<Mutex<Vec<u64>>>) -> Self {
        Self {
            lane,
            cost,
            id,
            executed_ids,
        }
    }
}

impl Schedulable for IdCountingWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.executed_ids.lock().unwrap().push(self.id);
        Ok(())
    }
}

// =========================================================================
// SlowWork: simulates a slow task for timing-sensitive tests
// =========================================================================

struct SlowWork {
    lane: SchedulingLane,
    cost: u64,
    delay_ms: u64,
    started: Arc<AtomicU64>,
    finished: Arc<AtomicU64>,
}

impl SlowWork {
    fn new(
        lane: SchedulingLane,
        cost: u64,
        delay_ms: u64,
        started: Arc<AtomicU64>,
        finished: Arc<AtomicU64>,
    ) -> Self {
        Self {
            lane,
            cost,
            delay_ms,
            started,
            finished,
        }
    }
}

impl Schedulable for SlowWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.started.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(self.delay_ms));
        self.finished.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

// =========================================================================
// High-volume stress: 10K tasks with random priorities
// =========================================================================

#[test]
fn stress_10k_random_priorities_no_lost_items() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let executed = Arc::new(Mutex::new(Vec::new()));
    let n: u64 = 10_000;

    // Use a simple deterministic pseudo-random sequence for reproducibility.
    // LCG: seed=42, multiplier=6364136223846793005, increment=1.
    let mut rng: u64 = 42;
    let lanes: [SchedulingLane; 5] = [
        SchedulingLane::Critical,
        SchedulingLane::Writeback,
        SchedulingLane::Prefetch,
        SchedulingLane::Maintenance,
        SchedulingLane::Idle,
    ];

    for id in 0..n {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let lane_idx = (rng >> 32) as usize % 5;
        s.submit(Box::new(IdCountingWork::new(
            lanes[lane_idx],
            1,
            id,
            executed.clone(),
        )));
    }

    let mut processed = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => processed += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected budget exhaustion"),
        }
    }

    assert_eq!(processed, n);
    assert_eq!(s.work_queued(), 0);

    let ids = executed.lock().unwrap();
    assert_eq!(ids.len() as u64, n);

    // Verify no duplicate IDs.
    let mut sorted = ids.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len() as u64, n, "duplicate executions detected");
}

#[test]
fn stress_10k_all_same_lane_fifo_preserved() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let executed = Arc::new(Mutex::new(Vec::new()));
    let n: u64 = 10_000;

    for id in 0..n {
        s.submit(Box::new(IdCountingWork::new(
            SchedulingLane::Critical,
            1,
            id,
            executed.clone(),
        )));
    }

    let mut processed = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => processed += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    assert_eq!(processed, n);
    let ids = executed.lock().unwrap();
    assert_eq!(ids.len() as u64, n);

    // FIFO order within same lane.
    for (i, &id) in ids.iter().enumerate() {
        assert_eq!(id, i as u64, "FIFO violation at position {i}");
    }
}

#[test]
fn stress_10k_lane_queue_weighted_dispatch_all_drained() {
    let mut q: LaneQueue<u64> = LaneQueue::new();
    let n: u64 = 10_000;

    let mut rng: u64 = 12345;
    for id in 0..n {
        rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
        let class_idx = (rng >> 32) as usize % 5;
        let class = SchedulingClass::from_index(class_idx).unwrap();
        q.push(class, id);
    }

    let mut popped = 0u64;
    let mut seen = Vec::with_capacity(n as usize);
    while let Some((_class, id)) = q.pop() {
        seen.push(id);
        popped += 1;
    }

    assert_eq!(popped, n);
    assert!(q.is_empty());

    // No duplicates.
    seen.sort();
    seen.dedup();
    assert_eq!(seen.len() as u64, n);
}

// =========================================================================
// Timing-sensitive: slow tasks don't starve fast tasks indefinitely
// =========================================================================

#[test]
fn slow_task_delays_subsequent_tasks_but_all_complete() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let started = Arc::new(AtomicU64::new(0));
    let finished = Arc::new(AtomicU64::new(0));

    // Submit one slow task (100ms) followed by 10 fast tasks.
    s.submit(Box::new(SlowWork::new(
        SchedulingLane::Critical,
        1,
        100,
        started.clone(),
        finished.clone(),
    )));

    for _ in 0..10 {
        s.submit(Box::new(SlowWork::new(
            SchedulingLane::Critical,
            1,
            0,
            started.clone(),
            finished.clone(),
        )));
    }

    let t0 = Instant::now();
    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }
    let elapsed = t0.elapsed();

    // All 11 tasks completed.
    assert_eq!(started.load(Ordering::SeqCst), 11);
    assert_eq!(finished.load(Ordering::SeqCst), 11);

    // The slow task (100ms) should dominate elapsed time.
    // poll() is single-threaded, so total time >= 100ms.
    assert!(
        elapsed >= Duration::from_millis(100),
        "expected at least 100ms for slow task, got {elapsed:?}"
    );
    // Should complete in reasonable time (not > 2s).
    assert!(
        elapsed < Duration::from_millis(2000),
        "timed out waiting for poll, took {elapsed:?}"
    );
}

#[test]
fn slow_task_in_low_priority_does_not_block_critical() {
    // A slow task in Idle lane should not delay Critical lane tasks.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let order = Arc::new(Mutex::new(Vec::new()));

    // Slow Idle task.
    struct TaggedSlowWork {
        lane: SchedulingLane,
        cost: u64,
        delay_ms: u64,
        tag: String,
        log: Arc<Mutex<Vec<String>>>,
    }

    impl Schedulable for TaggedSlowWork {
        fn lane(&self) -> SchedulingLane {
            self.lane
        }
        fn cost_hint(&self) -> u64 {
            self.cost
        }
        fn run(&mut self) -> Result<(), SchedulerWorkError> {
            self.log.lock().unwrap().push(self.tag.clone());
            std::thread::sleep(Duration::from_millis(self.delay_ms));
            Ok(())
        }
    }

    // Submit a slow Idle task.
    s.submit(Box::new(TaggedSlowWork {
        lane: SchedulingLane::Idle,
        cost: 1,
        delay_ms: 200,
        tag: "slow-idle".into(),
        log: order.clone(),
    }));

    // Submit two Critical tasks.
    s.submit(Box::new(TaggedSlowWork {
        lane: SchedulingLane::Critical,
        cost: 1,
        delay_ms: 0,
        tag: "crit-1".into(),
        log: order.clone(),
    }));
    s.submit(Box::new(TaggedSlowWork {
        lane: SchedulingLane::Critical,
        cost: 1,
        delay_ms: 0,
        tag: "crit-2".into(),
        log: order.clone(),
    }));

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let log = order.lock().unwrap();
    // Critical tasks must execute before the slow Idle task.
    let crit1_pos = log.iter().position(|t| t == "crit-1").unwrap();
    let crit2_pos = log.iter().position(|t| t == "crit-2").unwrap();
    let slow_pos = log.iter().position(|t| t == "slow-idle").unwrap();
    assert!(
        crit1_pos < slow_pos,
        "Critical task should run before slow Idle"
    );
    assert!(
        crit2_pos < slow_pos,
        "Critical task should run before slow Idle"
    );
}

// =========================================================================
// Burst submission timing
// =========================================================================

#[test]
fn burst_submission_1000_tasks_completes_in_reasonable_time() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let n: u64 = 1000;

    let t0 = Instant::now();
    for id in 0..n {
        s.submit(Box::new(IdCountingWork::new(
            SchedulingLane::Critical,
            1,
            id,
            Arc::new(Mutex::new(Vec::new())),
        )));
    }
    let submit_time = t0.elapsed();

    let mut processed = 0u64;
    let drain_t0 = Instant::now();
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => processed += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }
    let drain_time = drain_t0.elapsed();

    assert_eq!(processed, n);
    assert!(
        submit_time < Duration::from_secs(5),
        "submission too slow: {submit_time:?}"
    );
    assert!(
        drain_time < Duration::from_secs(5),
        "drain too slow: {drain_time:?}"
    );
}

#[test]
fn burst_mixed_priorities_completes_with_correct_counts() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let n_per_lane: u64 = 200;
    let lanes = SchedulingLane::ALL;

    for &lane in &lanes {
        for id in 0..n_per_lane {
            s.submit(Box::new(IdCountingWork::new(
                lane,
                1,
                id,
                Arc::new(Mutex::new(Vec::new())),
            )));
        }
    }

    let mut total = 0u64;
    loop {
        match s.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    assert_eq!(total, n_per_lane * 5);
    assert_eq!(s.work_queued(), 0);
}

// =========================================================================
// Starvation freedom under adversarial lane loading
// =========================================================================

#[test]
fn lane_queue_starvation_free_under_critical_flood() {
    // Flood Critical lane, verify low-priority items still get served.
    let mut q: LaneQueue<u64> = LaneQueue::new();

    // Push BestEffort items.
    for i in 0..10 {
        q.push(SchedulingClass::BestEffort, 10000 + i);
    }

    // Push many Critical items.
    for i in 0..500 {
        q.push(SchedulingClass::Critical, i);
    }

    let mut be_served = 0;
    let mut total_pops = 0u64;
    while let Some((class, _val)) = q.pop() {
        total_pops += 1;
        if class == SchedulingClass::BestEffort {
            be_served += 1;
        }
    }

    assert_eq!(total_pops, 510);
    assert_eq!(
        be_served, 10,
        "all BestEffort items must be served via starvation prevention"
    );
}

#[test]
fn lane_queue_weighted_balance_under_mixed_load() {
    // Mix all 5 classes evenly, verify weighted dispatch favors
    // higher-priority classes while not starving lower ones.
    let mut q: LaneQueue<u64> = LaneQueue::new();
    let n_per_class: u64 = 100;

    for _ in 0..n_per_class {
        q.push(SchedulingClass::Critical, 0);
        q.push(SchedulingClass::High, 1);
        q.push(SchedulingClass::Normal, 2);
        q.push(SchedulingClass::Low, 3);
        q.push(SchedulingClass::BestEffort, 4);
    }

    let mut counts = [0u64; 5];
    let mut critical_gap = 0u64;
    let mut max_critical_gap_while_critical_nonempty = 0u64;
    let mut critical_remaining = n_per_class;

    while let Some((class, _val)) = q.pop() {
        counts[class.index()] += 1;

        if class == SchedulingClass::Critical {
            critical_gap = 0;
            critical_remaining -= 1;
        } else {
            critical_gap += 1;
        }
        // Only measure gap while Critical lane is non-empty.
        if critical_remaining > 0 {
            max_critical_gap_while_critical_nonempty =
                max_critical_gap_while_critical_nonempty.max(critical_gap);
        }
    }

    // All items drained.
    for (i, &c) in counts.iter().enumerate() {
        assert_eq!(c, n_per_class, "class {i} count mismatch");
    }

    // While Critical lane still had items, gaps should be bounded
    // (weighted round-robin with starvation guard at 100).
    assert!(
        max_critical_gap_while_critical_nonempty <= 120,
        "Critical gap {max_critical_gap_while_critical_nonempty} exceeds reasonable bound while Critical still queued"
    );
}
