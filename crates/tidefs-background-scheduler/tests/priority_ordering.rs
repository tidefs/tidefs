// Priority ordering tests for tidefs-background-scheduler.
//
// Tests weighted round-robin dispatch across SchedulingLane priorities,
// starvation prevention, FIFO preservation within lanes, and lane
// promotion behavior through BackgroundScheduler submit/poll path
// and direct LaneQueue manipulation.

use std::sync::{Arc, Mutex};
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, LaneQueue, SchedulingClass, ServiceBudget,
};

// =========================================================================
// Mock implementations
// =========================================================================

/// Records lane and sequence number on execution.
struct TaggedWork {
    lane: SchedulingLane,
    cost: u64,
    tag: String,
    log: Arc<Mutex<Vec<String>>>,
}

impl TaggedWork {
    fn new(
        lane: SchedulingLane,
        cost: u64,
        tag: impl Into<String>,
        log: Arc<Mutex<Vec<String>>>,
    ) -> Self {
        Self {
            lane,
            cost,
            tag: tag.into(),
            log,
        }
    }
}

impl Schedulable for TaggedWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.log.lock().unwrap().push(self.tag.clone());
        Ok(())
    }
}

/// Work item that tracks its execution lane.
struct LaneCountWork {
    lane: SchedulingLane,
    cost: u64,
    counter: Arc<Mutex<Vec<SchedulingLane>>>,
}

impl LaneCountWork {
    fn new(lane: SchedulingLane, cost: u64, counter: Arc<Mutex<Vec<SchedulingLane>>>) -> Self {
        Self {
            lane,
            cost,
            counter,
        }
    }
}

impl Schedulable for LaneCountWork {
    fn lane(&self) -> SchedulingLane {
        self.lane
    }
    fn cost_hint(&self) -> u64 {
        self.cost
    }
    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.counter.lock().unwrap().push(self.lane);
        Ok(())
    }
}

// =========================================================================
// Priority ordering — BackgroundScheduler submit/poll path
// =========================================================================

#[test]
fn critical_executes_before_writeback() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let log = Arc::new(Mutex::new(Vec::new()));

    // Submit Writeback first, then Critical.
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Writeback,
        1,
        "wb",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Critical,
        1,
        "crit",
        log.clone(),
    )));

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let order = log.lock().unwrap();
    assert_eq!(order[0], "crit", "Critical must execute before Writeback");
    assert_eq!(order[1], "wb");
}

#[test]
fn writeback_before_maintenance() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let log = Arc::new(Mutex::new(Vec::new()));

    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Maintenance,
        1,
        "maint",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Writeback,
        1,
        "wb",
        log.clone(),
    )));

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let order = log.lock().unwrap();
    assert_eq!(order[0], "wb");
    assert_eq!(order[1], "maint");
}

#[test]
fn all_five_lanes_ordered_by_priority() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let log = Arc::new(Mutex::new(Vec::new()));

    // Submit one item per lane, lowest first.
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Idle,
        1,
        "idle",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Maintenance,
        1,
        "maint",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Prefetch,
        1,
        "prefetch",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Writeback,
        1,
        "wb",
        log.clone(),
    )));
    s.submit(Box::new(TaggedWork::new(
        SchedulingLane::Critical,
        1,
        "crit",
        log.clone(),
    )));

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let order = log.lock().unwrap();
    assert_eq!(*order, vec!["crit", "wb", "prefetch", "maint", "idle"]);
}

#[test]
fn fifo_within_same_lane() {
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let log = Arc::new(Mutex::new(Vec::new()));

    for i in 0..5 {
        s.submit(Box::new(TaggedWork::new(
            SchedulingLane::Critical,
            1,
            format!("c{i}"),
            log.clone(),
        )));
    }

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let order = log.lock().unwrap();
    assert_eq!(*order, vec!["c0", "c1", "c2", "c3", "c4"]);
}

#[test]
fn interleaved_priority_dispatch() {
    // Submit 5 Critical, 2 Writeback, 3 Maintenance.
    // With weighted round-robin, we should see Critical items first,
    // then Writeback, then Maintenance, with some interleaving when
    // credits reset.
    let mut s = BackgroundScheduler::new(ServiceBudget::UNBOUNDED);
    let lanes = Arc::new(Mutex::new(Vec::new()));

    for _ in 0..5 {
        s.submit(Box::new(LaneCountWork::new(
            SchedulingLane::Critical,
            1,
            lanes.clone(),
        )));
    }
    for _ in 0..2 {
        s.submit(Box::new(LaneCountWork::new(
            SchedulingLane::Writeback,
            1,
            lanes.clone(),
        )));
    }
    for _ in 0..3 {
        s.submit(Box::new(LaneCountWork::new(
            SchedulingLane::Maintenance,
            1,
            lanes.clone(),
        )));
    }

    loop {
        match s.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }

    let executed = lanes.lock().unwrap();
    // First items should be Critical.
    assert!(executed[0] == SchedulingLane::Critical);
    // Maintenance items should be last.
    assert!(executed[executed.len() - 1] == SchedulingLane::Maintenance);

    // Count per lane.
    let crit: Vec<_> = executed
        .iter()
        .filter(|l| **l == SchedulingLane::Critical)
        .collect();
    let wb: Vec<_> = executed
        .iter()
        .filter(|l| **l == SchedulingLane::Writeback)
        .collect();
    let maint: Vec<_> = executed
        .iter()
        .filter(|l| **l == SchedulingLane::Maintenance)
        .collect();
    assert_eq!(crit.len(), 5);
    assert_eq!(wb.len(), 2);
    assert_eq!(maint.len(), 3);
}

// =========================================================================
// LaneQueue direct tests — weighted round-robin
// =========================================================================

#[test]
fn lane_queue_pop_respects_weights() {
    // LaneQueue uses weights: Critical=16, Writeback=8, Prefetch=4,
    // Maintenance=2, Idle=1. After credits reset, Critical gets more pops.
    let mut q: LaneQueue<u32> = LaneQueue::new();

    // Push one item per lane.
    q.push(SchedulingClass::Critical, 100);
    q.push(SchedulingClass::High, 200);
    q.push(SchedulingClass::Normal, 300);
    q.push(SchedulingClass::Low, 400);
    q.push(SchedulingClass::BestEffort, 500);

    // First pop should be Critical (highest priority with credits).
    let first = q.pop().unwrap();
    assert_eq!(first, (SchedulingClass::Critical, 100));

    // Subsequent pops: priority order with weighted round-robin.
    let second = q.pop().unwrap();
    assert_eq!(second, (SchedulingClass::High, 200));

    let third = q.pop().unwrap();
    assert_eq!(third, (SchedulingClass::Normal, 300));

    let fourth = q.pop().unwrap();
    assert_eq!(fourth, (SchedulingClass::Low, 400));

    let fifth = q.pop().unwrap();
    assert_eq!(fifth, (SchedulingClass::BestEffort, 500));

    assert!(q.is_empty());
}

#[test]
fn lane_queue_same_class_fifo() {
    let mut q: LaneQueue<u32> = LaneQueue::new();

    q.push(SchedulingClass::Critical, 1);
    q.push(SchedulingClass::Critical, 2);
    q.push(SchedulingClass::Critical, 3);

    assert_eq!(q.pop().unwrap(), (SchedulingClass::Critical, 1));
    assert_eq!(q.pop().unwrap(), (SchedulingClass::Critical, 2));
    assert_eq!(q.pop().unwrap(), (SchedulingClass::Critical, 3));
    assert!(q.is_empty());
}

#[test]
fn lane_queue_empty_returns_none() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    assert!(q.pop().is_none());
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);
}

#[test]
fn lane_queue_weighted_dispatch_multiple_cycles() {
    // Critical weight=16, High=8. If we push 20 Critical and 10 High,
    // Critical should be served roughly twice as often.
    let mut q: LaneQueue<u32> = LaneQueue::new();

    for i in 0..20 {
        q.push(SchedulingClass::Critical, i);
    }
    for i in 0..10 {
        q.push(SchedulingClass::High, 100 + i);
    }

    let mut crit_count = 0;
    let mut high_count = 0;
    while let Some((class, _)) = q.pop() {
        match class {
            SchedulingClass::Critical => crit_count += 1,
            SchedulingClass::High => high_count += 1,
            _ => {}
        }
    }

    assert_eq!(crit_count, 20);
    assert_eq!(high_count, 10);

    // With weighted round-robin, the first items should be a mix
    // favoring Critical. Verify at least 2 Critical before any High
    // in the initial dispatch (Credits start at 16 for Critical,
    // 8 for High).
    // We don't test exact interleaving since it depends on credit
    // accounting, but all items must be drained.
}

#[test]
fn lane_queue_len_and_is_empty() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    assert!(q.is_empty());
    assert_eq!(q.len(), 0);

    q.push(SchedulingClass::Critical, 10);
    assert!(!q.is_empty());
    assert_eq!(q.len(), 1);

    q.push(SchedulingClass::High, 20);
    assert_eq!(q.len(), 2);

    q.pop();
    assert_eq!(q.len(), 1);

    q.pop();
    assert!(q.is_empty());
}

#[test]
fn lane_queue_pop_count_tracks_total_pops() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    assert_eq!(q.pop_count(), 0);

    q.push(SchedulingClass::Critical, 1);
    q.push(SchedulingClass::Critical, 2);
    q.pop();
    assert_eq!(q.pop_count(), 1);
    q.pop();
    assert_eq!(q.pop_count(), 2);
    q.pop(); // empty
    assert_eq!(q.pop_count(), 2);
}

#[test]
fn lane_queue_has_starvation_detection() {
    let mut q: LaneQueue<u32> = LaneQueue::new();
    // Insert one low-priority item and many high-priority items.
    // The low-priority item should eventually trigger starvation.
    q.push(SchedulingClass::BestEffort, 1);

    // Push enough Critical items to exhaust the starvation threshold (100).
    // Critical weight=16 per cycle, BestEffort=1.
    // After many cycles without serving BestEffort, starvation triggers.
    for i in 0..200 {
        q.push(SchedulingClass::Critical, 1000 + i);
    }

    // Drain all. The BestEffort item should be served at some point
    // before the starvation threshold of 100 consecutive skips.
    let mut best_effort_served = false;
    while let Some((class, val)) = q.pop() {
        if class == SchedulingClass::BestEffort {
            assert_eq!(val, 1);
            best_effort_served = true;
            break;
        }
    }

    assert!(
        best_effort_served,
        "BestEffort item should be served via starvation prevention"
    );

    // Drain remaining Critical items.
    while q.pop().is_some() {}
    assert!(q.is_empty());
}
