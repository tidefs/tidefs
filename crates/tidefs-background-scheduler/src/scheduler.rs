// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Async task scheduler backed by a 5-lane priority [`LaneQueue`].
//!
//! The [`Scheduler`] accepts futures submitted with a [`SchedulingClass`]
//! and drains them according to weighted round-robin priority dispatch.
//! Worker tasks poll the lane queue and execute futures to completion.
//!
//! # Example
//!
//! ```ignore
//! use tidefs_background_scheduler::{SchedulingClass, scheduler::Scheduler};
//!
//! let scheduler = Scheduler::new(4); // 4 worker tasks
//! scheduler.submit(SchedulingClass::Critical, async { critical_work().await });
//! scheduler.submit(SchedulingClass::Normal, async { normal_work().await });
//! scheduler.spawn(); // start workers
//! ```

use crate::{LaneQueue, SchedulingClass};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;

/// A boxed, pinned future that is `Send` and has a `()` output.
type BoxedFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

// ---------------------------------------------------------------------------
// SchedulerStats — per-lane observability
// ---------------------------------------------------------------------------

/// Per-lane statistics for scheduler observability.
#[derive(Clone, Debug, Default)]
pub struct SchedulerStats {
    /// Number of items submitted per lane since creation.
    pub submitted: [u64; SchedulingClass::LANE_COUNT],
    /// Number of items completed per lane since creation.
    pub completed: [u64; SchedulingClass::LANE_COUNT],
    /// Current queue depth per lane.
    pub depth: [usize; SchedulingClass::LANE_COUNT],
    /// Number of starvation events detected since creation.
    pub starvation_events: u64,
    /// Total number of futures executed.
    pub total_completed: u64,
    /// Number of worker tasks actively draining the queue.
    pub active_workers: usize,
}

// ---------------------------------------------------------------------------
// Scheduler — async 5-lane priority task scheduler
// ---------------------------------------------------------------------------

/// A priority-based async task scheduler.
///
/// Accepts futures (`Future<Output = ()> + Send + 'static`) submitted
/// with a [`SchedulingClass`]. A configurable number of worker tasks
/// drain the lane queue according to the weighted round-robin algorithm
/// defined by [`LaneQueue`].
///
/// # Starvation Guarantee
///
/// The underlying [`LaneQueue`] guarantees that no non-empty lane is
/// skipped more than [`STARVATION_THRESHOLD`] consecutive times. This
/// means Critical and High futures will execute within bounded time
/// even under heavy BestEffort load.
pub struct Scheduler {
    /// Shared lane queue.
    queue: Arc<Mutex<LaneQueue<BoxedFuture>>>,

    /// Worker task join handles.
    workers: Vec<tokio::task::JoinHandle<()>>,

    /// Per-lane submission counters (updated by submit).
    submitted: [u64; SchedulingClass::LANE_COUNT],

    /// Per-lane completion counters (updated atomically by workers).
    completed: Arc<[AtomicU64; SchedulingClass::LANE_COUNT]>,

    /// Total completed futures (updated atomically by workers).
    total_completed: Arc<AtomicU64>,

    /// Starvation events detected (updated atomically by workers).
    starvation_events: Arc<AtomicU64>,

    /// Number of worker tasks.
    worker_count: usize,
}

impl Scheduler {
    /// Create a new scheduler with `worker_count` worker tasks.
    ///
    /// Workers are not started until [`spawn`](Scheduler::spawn) is called.
    #[must_use]
    pub fn new(worker_count: usize) -> Self {
        assert!(worker_count > 0, "worker_count must be >= 1");
        let completed_arr: [AtomicU64; SchedulingClass::LANE_COUNT] = [
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
            AtomicU64::new(0),
        ];
        Self {
            queue: Arc::new(Mutex::new(LaneQueue::new())),
            workers: Vec::with_capacity(worker_count),
            submitted: [0; SchedulingClass::LANE_COUNT],
            completed: Arc::new(completed_arr),
            total_completed: Arc::new(AtomicU64::new(0)),
            starvation_events: Arc::new(AtomicU64::new(0)),
            worker_count,
        }
    }

    /// Submit a future for execution at the given scheduling class.
    ///
    /// The future is enqueued into the lane corresponding to `class`
    /// and will be polled to completion by a worker task after
    /// [`spawn`](Scheduler::spawn) is called.
    ///
    /// # Panics
    ///
    /// Panics if called after [`shutdown`](Scheduler::shutdown).
    pub fn submit<F>(&mut self, class: SchedulingClass, future: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let boxed: BoxedFuture = Box::pin(future);
        // We hold the lock briefly to push, then drop it.
        // In practice, this is called before spawn() or infrequently.
        // For high-frequency submission, callers should batch or use
        // a channel-based submission path.
        self.queue.lock().unwrap().push(class, boxed);
        self.submitted[class.index()] += 1;
    }

    /// Start worker tasks. Each worker runs a loop that pops futures
    /// from the shared lane queue and awaits them to completion.
    ///
    /// Workers run until the lane queue is empty and no more futures
    /// are submitted, or until [`shutdown`](Scheduler::shutdown) is called.
    ///
    /// # Panics
    ///
    /// Panics if called more than once.
    pub fn spawn(&mut self) {
        assert!(
            self.workers.is_empty(),
            "spawn called more than once on Scheduler"
        );

        for _ in 0..self.worker_count {
            let queue = self.queue.clone();
            let completed = self.completed.clone();
            let total_completed = self.total_completed.clone();
            let starvation_events = self.starvation_events.clone();
            let handle = tokio::spawn(async move {
                loop {
                    let (class_opt, maybe_future) = {
                        let mut q = queue.lock().unwrap();
                        let popped = q.pop();
                        let class = popped.as_ref().map(|(c, _)| *c);
                        let fut = popped.map(|(_, fut)| fut);
                        // Track starvation if detected.
                        if q.has_starvation() {
                            starvation_events.fetch_add(1, Ordering::Relaxed);
                        }
                        (class, fut)
                    };

                    match maybe_future {
                        Some(future) => {
                            future.await;
                            // Increment per-lane and total completion counters.
                            if let Some(class) = class_opt {
                                completed[class.index()].fetch_add(1, Ordering::Relaxed);
                            }
                            total_completed.fetch_add(1, Ordering::Relaxed);
                        }
                        None => {
                            // Queue is empty; exit the worker.
                            break;
                        }
                    }
                }
            });
            self.workers.push(handle);
        }
    }

    /// Wait for all submitted futures to complete and shut down workers.
    ///
    /// This method waits for all worker tasks to finish. Workers exit
    /// when the lane queue is empty. After shutdown, no new futures
    /// can be submitted.
    pub async fn shutdown(mut self) {
        // Drop the queue reference so workers see empty queue and exit.
        // Workers hold their own Arc references, so the queue stays
        // alive until all workers have exited.
        for handle in self.workers.drain(..) {
            let _ = handle.await;
        }
    }

    /// Return a snapshot of current scheduler statistics.
    #[must_use]
    pub fn stats(&self) -> SchedulerStats {
        let depth: [usize; SchedulingClass::LANE_COUNT] = {
            let q = self.queue.lock().unwrap();
            let mut d = [0usize; SchedulingClass::LANE_COUNT];
            for class in &SchedulingClass::ALL {
                d[class.index()] = q.lane_len(*class);
            }
            d
        };

        let mut completed = [0u64; SchedulingClass::LANE_COUNT];
        for (i, c) in self.completed.iter().enumerate() {
            completed[i] = c.load(Ordering::Relaxed);
        }

        SchedulerStats {
            submitted: self.submitted,
            completed,
            depth,
            starvation_events: self.starvation_events.load(Ordering::Relaxed),
            total_completed: self.total_completed.load(Ordering::Relaxed),
            active_workers: self.worker_count,
        }
    }
}

impl std::fmt::Debug for Scheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scheduler")
            .field("worker_count", &self.worker_count)
            .field("submitted", &self.submitted)
            .field("queue_len", &self.queue.lock().unwrap().len())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scheduler_basic_submit_and_drain() {
        let mut s = Scheduler::new(2);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        for i in 0..10u32 {
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
        assert_eq!(results.len(), 10);
    }

    #[tokio::test]
    async fn scheduler_critical_runs_before_low() {
        let mut s = Scheduler::new(1);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        // Submit Low first, then Critical. Critical should run first.
        s.submit(SchedulingClass::Low, {
            let tx = tx.clone();
            async move {
                tx.send("low").unwrap();
            }
        });
        s.submit(SchedulingClass::Critical, {
            let tx = tx.clone();
            async move {
                tx.send("critical").unwrap();
            }
        });
        drop(tx);

        s.spawn();
        s.shutdown().await;

        let first = rx.try_recv().unwrap();
        assert_eq!(first, "critical", "Critical should run before Low");
    }

    #[tokio::test]
    async fn scheduler_multiple_workers_drain_fully() {
        let mut s = Scheduler::new(4);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let count = 100u32;

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
        assert_eq!(results.len(), count as usize);
    }

    #[tokio::test]
    async fn scheduler_empty_queue_workers_exit() {
        let mut s = Scheduler::new(2);

        // Submit nothing; workers should exit immediately.
        s.spawn();
        s.shutdown().await;

        // No panic = workers exited cleanly.
    }

    #[tokio::test]
    async fn scheduler_stats_tracks_submissions() {
        let mut s = Scheduler::new(1);

        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

        s.submit(SchedulingClass::Critical, {
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
        s.submit(SchedulingClass::BestEffort, {
            let tx = tx.clone();
            async move {
                tx.send(()).unwrap();
            }
        });
        drop(tx);

        let stats = s.stats();
        assert_eq!(stats.submitted[SchedulingClass::Critical.index()], 1);
        assert_eq!(stats.submitted[SchedulingClass::Normal.index()], 1);
        assert_eq!(stats.submitted[SchedulingClass::BestEffort.index()], 1);
        assert_eq!(stats.active_workers, 1);

        s.spawn();
        s.shutdown().await;

        // Drain the results.
        while rx.try_recv().is_ok() {}
    }

    #[test]
    #[should_panic(expected = "worker_count must be >= 1")]
    fn scheduler_zero_workers_panics() {
        let _ = Scheduler::new(0);
    }

    #[test]
    #[should_panic(expected = "spawn called more than once")]
    fn scheduler_double_spawn_panics() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        rt.block_on(async {
            let mut s = Scheduler::new(1);
            s.spawn();
            // Should not be able to spawn again.
            s.spawn();
        });
    }
}
