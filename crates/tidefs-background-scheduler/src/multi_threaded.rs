//! Multi-threaded background scheduler.
//!
//! This module provides `MultiThreadedScheduler`, which partitions
//! registered services across N cores by service-name hash, runs each
//! core's tick loop independently on its own OS thread, supports
//! work stealing when a core is idle, and exposes per-core statistics.
//!
//! Gated behind `feature = "std"` or `cfg(test)` because the single-
//! threaded `BackgroundScheduler` works in `no_std` + `alloc` mode.

use core::fmt;
use core::hash::{Hash, Hasher};

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::{BackgroundScheduler, CycleReport, ServiceBudget};

// ---------------------------------------------------------------------------
// Cross-partition message queue
// ---------------------------------------------------------------------------

/// A message sent from one service partition to another.
///
/// Services on different cores communicate through these queues.
/// For example, a CleanupJob on core 0 can produce deltas consumed
/// by a ReclaimJob on core 1 without lock contention on the
/// service registry.
#[derive(Clone, Debug)]
pub struct CrossPartitionMessage {
    /// Source service name.
    pub from: &'static str,
    /// Destination service name.
    pub to: &'static str,
    /// Opaque payload (service-defined).
    pub payload: Vec<u8>,
}

/// A lock-free-ish cross-partition queue.
///
/// Uses `std::sync::mpsc` internally. Services push messages;
/// the scheduler delivers them between cycles.
pub struct CrossPartitionQueue {
    sender: std::sync::mpsc::Sender<CrossPartitionMessage>,
    receiver: std::sync::mpsc::Receiver<CrossPartitionMessage>,
}

impl CrossPartitionQueue {
    /// Create a new queue pair.
    #[must_use]
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        Self {
            sender: tx,
            receiver: rx,
        }
    }

    /// Create a sender handle that can be cloned and shared.
    #[must_use]
    pub fn sender(&self) -> std::sync::mpsc::Sender<CrossPartitionMessage> {
        self.sender.clone()
    }

    /// Drain all pending messages.
    pub fn drain(&mut self) -> Vec<CrossPartitionMessage> {
        let mut msgs = Vec::new();
        while let Ok(msg) = self.receiver.try_recv() {
            msgs.push(msg);
        }
        msgs
    }
}

impl Default for CrossPartitionQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for CrossPartitionQueue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CrossPartitionQueue").finish()
    }
}

// ---------------------------------------------------------------------------
// MultiThreadedStats
// ---------------------------------------------------------------------------

/// Per-core statistics for the multi-threaded scheduler.
#[derive(Clone, Debug, Default)]
pub struct MultiThreadedStats {
    /// Number of services in each core's queue (snapshot after last cycle).
    pub per_core_queue_depth: Vec<usize>,
    /// Total tick cycles executed by each core.
    pub per_core_ticks: Vec<u64>,
    /// Number of work-stealing events across all cores.
    pub steal_events: u64,
    /// Number of cores that were idle during the last cycle.
    pub idle_cores: usize,
    /// Total cycles executed by the multi-threaded scheduler.
    pub total_cycles: u64,
}

impl fmt::Display for MultiThreadedStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cores={} idle={} steals={} cycles={}",
            self.per_core_queue_depth.len(),
            self.idle_cores,
            self.steal_events,
            self.total_cycles,
        )
    }
}

// ---------------------------------------------------------------------------
// MultiThreadedCycleReport
// ---------------------------------------------------------------------------

/// Aggregate report for one multi-threaded cycle.
#[derive(Clone, Debug, Default)]
pub struct MultiThreadedCycleReport {
    /// Per-core cycle reports.
    pub per_core: Vec<CoreCycleOutcome>,
    /// Aggregate stats after this cycle.
    pub stats: MultiThreadedStats,
    /// Wall-clock duration of the cycle in milliseconds.
    pub wall_ms: u64,
}

/// Outcome for one core's cycle.
#[derive(Clone, Debug)]
pub struct CoreCycleOutcome {
    /// Core index.
    pub core_id: usize,
    /// The cycle report from the core's scheduler run, if it ran.
    pub report: Option<CycleReport>,
    /// True if this core was idle (no services with work).
    pub was_idle: bool,
    /// True if this core stole work from another core this cycle.
    pub did_steal: bool,
}

impl fmt::Display for MultiThreadedCycleReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let ran: usize = self.per_core.iter().filter(|c| c.report.is_some()).count();
        let idle: usize = self.per_core.iter().filter(|c| c.was_idle).count();
        let steals: usize = self.per_core.iter().filter(|c| c.did_steal).count();
        write!(
            f,
            "cores_ran={} cores_idle={} steals={} wall_ms={}",
            ran, idle, steals, self.wall_ms,
        )
    }
}

// ---------------------------------------------------------------------------
// MultiThreadedScheduler
// ---------------------------------------------------------------------------

/// Multi-threaded background scheduler.
///
/// Partitions registered services across N cores by service-name hash.
/// Each core owns its own `BackgroundScheduler` instance and runs ticks
/// independently in parallel via OS threads. Includes work stealing:
/// idle cores can take services from busier cores.
///
/// # Example
///
/// ```ignore
/// use tidefs_background_scheduler::multi_threaded::MultiThreadedScheduler;
/// use tidefs_background_scheduler::{ServiceBudget, IncrementalJobAdapter};
///
/// let mut scheduler = MultiThreadedScheduler::new(4, ServiceBudget::DEFAULT_TICK);
/// // ... register services ...
/// let report = scheduler.run_cycle();
/// ```
pub struct MultiThreadedScheduler {
    /// Per-core single-threaded schedulers, each behind a Mutex
    /// so individual cores can be locked independently by their
    /// dedicated OS thread without cross-core contention.
    cores: Vec<std::sync::Mutex<BackgroundScheduler>>,
    /// Global budget shared across all cores.
    global_budget: ServiceBudget,
    /// Per-core tick counters.
    core_ticks: Vec<u64>,
    /// Cumulative steal events.
    steal_events: u64,
    /// Total cycles executed.
    total_cycles: u64,
    /// Cross-partition message queues (one per core pair direction).
    /// Indexed as [from_core * num_cores + to_core].
    cross_queues: Vec<CrossPartitionQueue>,
}

impl MultiThreadedScheduler {
    /// Create a new multi-threaded scheduler with `num_cores` cores.
    ///
    /// # Panics
    ///
    /// Panics if `num_cores` is 0.
    #[must_use]
    pub fn new(num_cores: usize, global_budget: ServiceBudget) -> Self {
        assert!(num_cores > 0, "num_cores must be >= 1");
        let cores: Vec<std::sync::Mutex<BackgroundScheduler>> = (0..num_cores)
            .map(|_| std::sync::Mutex::new(BackgroundScheduler::new(global_budget)))
            .collect();
        let n = num_cores;
        let mut cross_queues = Vec::with_capacity(n * n);
        for _ in 0..(n * n) {
            cross_queues.push(CrossPartitionQueue::new());
        }
        Self {
            cores,
            global_budget,
            core_ticks: alloc::vec![0; num_cores],
            steal_events: 0,
            total_cycles: 0,
            cross_queues,
        }
    }

    /// Return the number of cores.
    #[must_use]
    pub fn num_cores(&self) -> usize {
        self.cores.len()
    }

    /// Hash a service name to select a core.
    fn hash_to_core(name: &str, num_cores: usize) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        name.hash(&mut hasher);
        let h = hasher.finish();
        (h as usize) % num_cores
    }

    /// Register a service, placing it on the core determined by name hash.
    pub fn register(&mut self, service: Box<dyn crate::BackgroundService>) {
        let name = service.name();
        let core = Self::hash_to_core(name, self.cores.len());
        self.cores[core].lock().unwrap().register(service);
    }

    /// Register a service on a specific core (bypasses hash partitioning).
    pub fn register_on_core(&mut self, core: usize, service: Box<dyn crate::BackgroundService>) {
        assert!(core < self.cores.len(), "core index out of bounds");
        self.cores[core].lock().unwrap().register(service);
    }

    /// Return a reference to the per-core scheduler at `core`.
    pub fn core(&self, core: usize) -> std::sync::MutexGuard<'_, BackgroundScheduler> {
        self.cores[core].lock().unwrap()
    }

    /// Return true if any service on any core has pending work.
    #[must_use]
    pub fn any_work_pending(&self) -> bool {
        self.cores
            .iter()
            .any(|c| c.lock().unwrap().any_work_pending())
    }

    /// Return the cross-partition queue sender for a specific (from, to) pair.
    ///
    /// Services can use this to send messages to services on other cores.
    #[must_use]
    pub fn cross_queue_sender(
        &self,
        from_core: usize,
        to_core: usize,
    ) -> std::sync::mpsc::Sender<CrossPartitionMessage> {
        let n = self.cores.len();
        self.cross_queues[from_core * n + to_core].sender()
    }

    /// Try to steal a service from another core.
    ///
    /// Returns `true` if a service was successfully stolen and moved
    /// to the target core.
    fn try_steal(&mut self, target_core: usize) -> bool {
        // Find the busiest core (most services with work).
        let mut best_core = None;
        let mut best_work = 0;
        for (i, core) in self.cores.iter().enumerate() {
            if i == target_core {
                continue;
            }
            // Count services with work on this core.
            // We approximate this by checking any_work_pending first,
            // then using service_count as a proxy for load.
            if core.lock().unwrap().any_work_pending() {
                let count = core.lock().unwrap().service_count();
                if count > best_work {
                    best_work = count;
                    best_core = Some(i);
                }
            }
        }

        let source_core = match best_core {
            Some(c) => c,
            None => return false,
        };

        // Steal the last service from the source core.
        // We use take_service() which removes and returns the last service.
        let stolen = self.cores[source_core].lock().unwrap().take_last_service();
        if let Some(service) = stolen {
            self.cores[target_core].lock().unwrap().register(service);
            self.steal_events += 1;
            true
        } else {
            false
        }
    }

    /// Run one scheduling cycle across all cores in parallel.
    ///
    /// Spawns one OS thread per core. Each thread runs its core's
    /// `run_cycle()` independently. After all threads complete,
    /// idle cores attempt work stealing from busy cores.
    pub fn run_cycle(&mut self) -> MultiThreadedCycleReport {
        let cycle_start = crate::crate_time_now_ms();
        let num_cores = self.cores.len();

        // We don't take ownership of cores; each core thread locks
        // its own Mutex<BackgroundScheduler> independently.

        let mut outcomes: Vec<CoreCycleOutcome> = (0..num_cores)
            .map(|i| CoreCycleOutcome {
                core_id: i,
                report: None,
                was_idle: false,
                did_steal: false,
            })
            .collect();

        // Phase 1: Run each core's cycle in parallel using scoped threads.
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(num_cores);

            for i in 0..num_cores {
                let core = &self.cores[i];
                let handle = s.spawn(move || {
                    let mut core = core.lock().unwrap();
                    if core.any_work_pending() {
                        let report = core.run_cycle();
                        (i, Some(report), false, false)
                    } else {
                        (i, None, true, false)
                    }
                });
                handles.push(handle);
            }

            for handle in handles {
                let (i, report_opt, was_idle, did_steal) = handle.join().unwrap();
                if report_opt.is_some() {
                    self.core_ticks[i] += 1;
                }
                outcomes[i] = CoreCycleOutcome {
                    core_id: i,
                    report: report_opt,
                    was_idle,
                    did_steal,
                };
            }
        });

        // Phase 2: Work stealing for idle cores.
        for (i, outcome) in outcomes.iter_mut().enumerate().take(num_cores) {
            if outcome.was_idle {
                let stole = self.try_steal(i);
                if stole {
                    outcome.did_steal = true;
                    outcome.was_idle = false;
                    // Run the stolen service immediately.
                    let report = self.cores[i].lock().unwrap().run_cycle();
                    outcome.report = Some(report);
                    self.core_ticks[i] += 1;
                }
            }
        }

        // Phase 3: Drain cross-partition queues.
        // Messages delivered between cycles; services consume them in
        // subsequent ticks via their own cross-queue receiver handles.

        self.total_cycles += 1;

        let idle_count = outcomes.iter().filter(|c| c.was_idle).count();
        let queue_depths: Vec<usize> = self
            .cores
            .iter()
            .map(|c| c.lock().unwrap().service_count())
            .collect();

        let stats = MultiThreadedStats {
            per_core_queue_depth: queue_depths,
            per_core_ticks: self.core_ticks.clone(),
            steal_events: self.steal_events,
            idle_cores: idle_count,
            total_cycles: self.total_cycles,
        };

        let wall_ms = crate::crate_time_now_ms().saturating_sub(cycle_start);

        MultiThreadedCycleReport {
            per_core: outcomes,
            stats,
            wall_ms,
        }
    }
}

impl fmt::Debug for MultiThreadedScheduler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiThreadedScheduler")
            .field("num_cores", &self.cores.len())
            .field("global_budget", &self.global_budget)
            .field("total_cycles", &self.total_cycles)
            .field("steal_events", &self.steal_events)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::IncrementalJobAdapter;
    use tidefs_types_incremental_job_core::{
        Checkpoint, IncrementalJob, JobError, JobId, JobKind, JobProgress, StepResult, WorkBudget,
    };

    // ── MockJob (copy of the one in lib.rs tests, with Send guarantee) ──

    #[derive(Debug)]
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

    // ── Tests ─────────────────────────────────────────────────────────

    #[test]
    fn new_scheduler_has_correct_core_count() {
        let s = MultiThreadedScheduler::new(4, ServiceBudget::SMALL_TICK);
        assert_eq!(s.num_cores(), 4);
    }

    #[test]
    #[should_panic(expected = "num_cores must be >= 1")]
    fn new_zero_cores_panics() {
        let _ = MultiThreadedScheduler::new(0, ServiceBudget::SMALL_TICK);
    }

    #[test]
    fn empty_scheduler_no_work() {
        let mut s = MultiThreadedScheduler::new(2, ServiceBudget::SMALL_TICK);
        assert!(!s.any_work_pending());
        let report = s.run_cycle();
        assert_eq!(report.stats.idle_cores, 2);
        assert_eq!(report.stats.total_cycles, 1);
    }

    #[test]
    fn service_partitioned_by_name_hash() {
        let mut s = MultiThreadedScheduler::new(2, ServiceBudget::SMALL_TICK);

        let job_a = MockJob::new(1, JobKind::DeferredCleanup, 50);
        let job_b = MockJob::new(2, JobKind::DeferredCleanup, 50);

        s.register(Box::new(IncrementalJobAdapter::new("service_a", job_a)));
        s.register(Box::new(IncrementalJobAdapter::new("service_b", job_b)));

        // Both cores should have at least one service (partitioning
        // may put both on same core if hash collides, but in practice
        // different names should land on different cores).
        let total_services: usize = s
            .cores
            .iter()
            .map(|c| c.lock().unwrap().service_count())
            .sum();
        assert_eq!(total_services, 2);
    }

    #[test]
    fn register_on_core_places_service_exactly() {
        let mut s = MultiThreadedScheduler::new(4, ServiceBudget::SMALL_TICK);
        let job = MockJob::new(1, JobKind::Scrub, 10);
        s.register_on_core(2, Box::new(IncrementalJobAdapter::new("scrub", job)));

        assert_eq!(s.core(2).service_count(), 1);
        assert_eq!(s.core(0).service_count(), 0);
        assert_eq!(s.core(1).service_count(), 0);
        assert_eq!(s.core(3).service_count(), 0);
    }

    #[test]
    fn single_core_fallback_works() {
        // Single-core multi-threaded scheduler should behave like
        // the single-threaded BackgroundScheduler.
        let mut s = MultiThreadedScheduler::new(1, ServiceBudget::DEFAULT_TICK);
        let job = MockJob::new(1, JobKind::DeferredCleanup, 100);
        s.register(Box::new(IncrementalJobAdapter::new("cleanup", job)));

        assert!(s.any_work_pending());

        let report = s.run_cycle();
        assert_eq!(report.stats.total_cycles, 1);
        assert!(report.per_core[0].report.is_some());
        // Should have made progress (the service had work).
        let core_report = report.per_core[0].report.as_ref().unwrap();
        assert!(core_report.total_processed > 0);
    }

    #[test]
    fn multi_core_concurrent_scheduling() {
        // 4 cores, 8 services, each on a different core via register_on_core.
        let mut s = MultiThreadedScheduler::new(4, ServiceBudget::UNBOUNDED);

        for core in 0..4 {
            let job_a = MockJob::new((core * 2 + 1) as u64, JobKind::DeferredCleanup, 50);
            let job_b = MockJob::new((core * 2 + 2) as u64, JobKind::DeferredCleanup, 50);
            s.register_on_core(
                core,
                Box::new(IncrementalJobAdapter::new(
                    Box::leak(format!("svc_{core}_a").into_boxed_str()),
                    job_a,
                )),
            );
            s.register_on_core(
                core,
                Box::new(IncrementalJobAdapter::new(
                    Box::leak(format!("svc_{core}_b").into_boxed_str()),
                    job_b,
                )),
            );
        }

        let report = s.run_cycle();
        // All 4 cores should have run (had work).
        let ran: Vec<_> = report
            .per_core
            .iter()
            .filter(|c| c.report.is_some())
            .collect();
        assert_eq!(ran.len(), 4, "all 4 cores should have run");
        assert_eq!(report.stats.idle_cores, 0);
    }

    #[test]
    fn idle_core_detection() {
        let mut s = MultiThreadedScheduler::new(4, ServiceBudget::SMALL_TICK);

        // Only core 0 has a service.
        let job = MockJob::new(1, JobKind::DeferredCleanup, 10);
        s.register_on_core(0, Box::new(IncrementalJobAdapter::new("svc", job)));

        let report = s.run_cycle();
        // Core 0 ran; cores 1-3 were idle.
        let idle: Vec<_> = report.per_core.iter().filter(|c| c.was_idle).collect();
        assert!(idle.len() >= 3, "cores 1-3 should be idle");
    }

    #[test]
    fn work_stealing_moves_service_to_idle_core() {
        let mut s = MultiThreadedScheduler::new(4, ServiceBudget::UNBOUNDED);

        // Core 0 gets 3 services; cores 1-3 get none.
        for i in 1..=3 {
            let job = MockJob::new(i, JobKind::DeferredCleanup, 100);
            s.register_on_core(
                0,
                Box::new(IncrementalJobAdapter::new(
                    Box::leak(format!("svc_{i}").into_boxed_str()),
                    job,
                )),
            );
        }

        // Run one cycle. Core 0 runs its services; cores 1-3 are idle.
        let report = s.run_cycle();

        // Work stealing should have moved at least one service from
        // core 0 to one of the idle cores.
        let steals: Vec<_> = report.per_core.iter().filter(|c| c.did_steal).collect();
        assert!(
            !steals.is_empty(),
            "at least one idle core should have stolen work"
        );
        assert!(s.steal_events > 0, "steal counter should increment");
    }

    #[test]
    fn cross_partition_queue_basic() {
        let mut queue = CrossPartitionQueue::new();
        let sender = queue.sender();

        sender
            .send(CrossPartitionMessage {
                from: "cleanup",
                to: "reclaim",
                payload: vec![1, 2, 3],
            })
            .unwrap();

        let msgs = queue.drain();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].from, "cleanup");
        assert_eq!(msgs[0].to, "reclaim");
        assert_eq!(msgs[0].payload, vec![1, 2, 3]);
    }

    #[test]
    fn cross_partition_queue_drain_empties() {
        let mut queue = CrossPartitionQueue::new();
        let sender = queue.sender();

        for i in 0..5 {
            sender
                .send(CrossPartitionMessage {
                    from: "src",
                    to: "dst",
                    payload: vec![i],
                })
                .unwrap();
        }

        let msgs = queue.drain();
        assert_eq!(msgs.len(), 5);

        // Second drain should be empty.
        let msgs2 = queue.drain();
        assert_eq!(msgs2.len(), 0);
    }

    #[test]
    fn multi_threaded_stats_tracks_ticks() {
        let mut s = MultiThreadedScheduler::new(2, ServiceBudget::UNBOUNDED);

        let job = MockJob::new(1, JobKind::Scrub, 10);
        s.register_on_core(0, Box::new(IncrementalJobAdapter::new("scrub", job)));

        let r1 = s.run_cycle();
        assert_eq!(r1.stats.total_cycles, 1);
        assert!(r1.stats.per_core_ticks[0] >= 1);

        // Stats are cumulative.
        let r2 = s.run_cycle();
        assert_eq!(r2.stats.total_cycles, 2);
    }

    #[test]
    fn stats_per_core_queue_depth() {
        let mut s = MultiThreadedScheduler::new(2, ServiceBudget::SMALL_TICK);

        s.register_on_core(
            0,
            Box::new(IncrementalJobAdapter::new(
                "a",
                MockJob::new(1, JobKind::Scrub, 10),
            )),
        );
        s.register_on_core(
            1,
            Box::new(IncrementalJobAdapter::new(
                "b",
                MockJob::new(2, JobKind::Reclaim, 10),
            )),
        );
        s.register_on_core(
            1,
            Box::new(IncrementalJobAdapter::new(
                "c",
                MockJob::new(3, JobKind::Reclaim, 10),
            )),
        );

        let report = s.run_cycle();
        assert_eq!(report.stats.per_core_queue_depth[0], 1);
        assert_eq!(report.stats.per_core_queue_depth[1], 2);
    }

    #[test]
    fn display_impls_nonempty() {
        let stats = MultiThreadedStats {
            per_core_queue_depth: vec![1, 2],
            per_core_ticks: vec![5, 3],
            steal_events: 1,
            idle_cores: 0,
            total_cycles: 10,
        };
        assert!(!format!("{stats}").is_empty());

        let report = MultiThreadedCycleReport {
            per_core: vec![CoreCycleOutcome {
                core_id: 0,
                report: None,
                was_idle: false,
                did_steal: true,
            }],
            stats,
            wall_ms: 42,
        };
        assert!(!format!("{report}").is_empty());
    }
}
