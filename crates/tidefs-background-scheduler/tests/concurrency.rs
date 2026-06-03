// Concurrency tests for tidefs-background-scheduler.
//
// Tests concurrent submission and draining through Arc<Mutex<BackgroundScheduler>>,
// verifying no lost or double-executed items under multi-threaded submission.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};
use tidefs_background_scheduler::{
    scheduling::{PollResult, Schedulable, SchedulerWorkError, SchedulingLane},
    BackgroundScheduler, ServiceBudget,
};

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

#[test]
fn concurrent_submission_no_lost_items() {
    let s = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let num_threads = 4;
    let items_per_thread: u64 = 200;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let s = s.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..items_per_thread {
                let lane = if i % 2 == 0 {
                    SchedulingLane::Critical
                } else {
                    SchedulingLane::Writeback
                };
                s.lock().unwrap().submit(Box::new(CountingWork::new(
                    lane,
                    1,
                    Arc::new(AtomicUsize::new(0)),
                )));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let mut scheduler = s.lock().unwrap();
    let mut total = 0u64;
    loop {
        match scheduler.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }
    assert_eq!(total, num_threads * items_per_thread);
    assert_eq!(scheduler.work_queued(), 0);
}

#[test]
fn concurrent_submission_interleaved_with_poll() {
    use std::sync::Barrier;
    let s = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let num_submitters = 2;
    let items_per: usize = 200;
    let barrier = Arc::new(Barrier::new(num_submitters + 1));

    let mut handles = Vec::new();
    for _ in 0..num_submitters {
        let s = s.clone();
        let b = barrier.clone();
        handles.push(std::thread::spawn(move || {
            b.wait();
            for i in 0..items_per {
                let lane = if i % 2 == 0 {
                    SchedulingLane::Critical
                } else {
                    SchedulingLane::Writeback
                };
                s.lock().unwrap().submit(Box::new(CountingWork::new(
                    lane,
                    1,
                    Arc::new(AtomicUsize::new(0)),
                )));
            }
        }));
    }

    let s_drain = s.clone();
    let b_drain = barrier.clone();
    let drain_handle = std::thread::spawn(move || {
        b_drain.wait();
        let mut drained = 0u64;
        loop {
            let result = {
                let mut scheduler = s_drain.lock().unwrap();
                scheduler.poll()
            };
            match result {
                PollResult::WorkDone {
                    items_processed, ..
                } => drained += items_processed,
                PollResult::Idle => {
                    // Check once more in case submitters added items.
                    let check = s_drain.lock().unwrap().work_queued();
                    if check == 0 {
                        break;
                    }
                }
                PollResult::BudgetExhausted => {}
            }
            std::thread::yield_now();
        }
        drained
    });

    for h in handles {
        h.join().unwrap();
    }
    let drained = drain_handle.join().unwrap();

    let mut scheduler = s.lock().unwrap();
    let mut remaining = 0u64;
    loop {
        match scheduler.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => remaining += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => {}
        }
    }
    assert_eq!(drained + remaining, (num_submitters * items_per) as u64);
    assert_eq!(scheduler.work_queued(), 0);
}

#[test]
fn concurrent_submission_no_double_execution() {
    let s = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let counter = Arc::new(AtomicUsize::new(0));
    let num_threads = 4;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let s = s.clone();
        let counter = counter.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..100 {
                s.lock().unwrap().submit(Box::new(CountingWork::new(
                    SchedulingLane::Critical,
                    1,
                    counter.clone(),
                )));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let mut scheduler = s.lock().unwrap();
    loop {
        match scheduler.poll() {
            PollResult::WorkDone { .. } => {}
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }
    assert_eq!(counter.load(Ordering::SeqCst), num_threads * 100);
}

#[test]
fn high_contention_submission_still_drains_all() {
    // 8 threads submitting rapidly with minimal yielding.
    let s = Arc::new(Mutex::new(BackgroundScheduler::new(
        ServiceBudget::UNBOUNDED,
    )));
    let num_threads = 8;
    let items_per = 50;

    let mut handles = Vec::new();
    for _ in 0..num_threads {
        let s = s.clone();
        handles.push(std::thread::spawn(move || {
            for _ in 0..items_per {
                s.lock().unwrap().submit(Box::new(CountingWork::new(
                    SchedulingLane::Critical,
                    1,
                    Arc::new(AtomicUsize::new(0)),
                )));
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let mut scheduler = s.lock().unwrap();
    let mut total = 0u64;
    loop {
        match scheduler.poll() {
            PollResult::WorkDone {
                items_processed, ..
            } => total += items_processed,
            PollResult::Idle => break,
            PollResult::BudgetExhausted => panic!("unexpected"),
        }
    }
    assert_eq!(total, num_threads * items_per);
}
