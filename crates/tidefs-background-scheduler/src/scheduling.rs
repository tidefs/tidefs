// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Work-item scheduling: per-lane priority queues with budget tracking,
//! starvation prevention, and poll-driven dispatch.
//!
//! This module implements the 5-lane priority scheduler specified in
//! issue #3607. Background subsystems (writeback, prefetch, dedup, rebuild,
//! GC) submit `Schedulable` work items into per-lane FIFO queues. The
//! `poll()` method drains lanes in priority order, enforcing per-tick
//! budget limits and promoting starved items to higher lanes.

use core::fmt;

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, collections::VecDeque};

// ── SchedulingLane ───────────────────────────────────────────────────

/// Five priority lanes for work-item dispatch.
///
/// Lanes are drained highest-first. Within a lane, items are FIFO.
/// Starvation prevention can promote items to a higher lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SchedulingLane {
    /// Authority/consistency work: may not be deferred.
    /// Examples: intent-log sync, repair, membership health.
    Critical = 0,

    /// Latency-sensitive cache writeback.
    /// Examples: dirty-page flush, inode-table writeback.
    Writeback = 1,

    /// Bulk throughput and prefetch work.
    /// Examples: dir-index readahead, metadata prefetch.
    Prefetch = 2,

    /// Deferred maintenance and compaction.
    /// Examples: dedup scanning, segment compaction, GC mark.
    Maintenance = 3,

    /// Speculative work: runs only when higher lanes are idle.
    /// Examples: thermal rebalance, idle verification.
    Idle = 4,
}

impl SchedulingLane {
    /// Number of lanes.
    pub const LANE_COUNT: usize = 5;

    /// All lanes in priority order.
    pub const ALL: [SchedulingLane; 5] = [
        SchedulingLane::Critical,
        SchedulingLane::Writeback,
        SchedulingLane::Prefetch,
        SchedulingLane::Maintenance,
        SchedulingLane::Idle,
    ];

    /// Human-readable label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            SchedulingLane::Critical => "critical",
            SchedulingLane::Writeback => "writeback",
            SchedulingLane::Prefetch => "prefetch",
            SchedulingLane::Maintenance => "maintenance",
            SchedulingLane::Idle => "idle",
        }
    }

    /// Next higher lane, or `None` if already at Critical.
    #[must_use]
    pub const fn promote(self) -> Option<SchedulingLane> {
        match self {
            SchedulingLane::Critical => None,
            SchedulingLane::Writeback => Some(SchedulingLane::Critical),
            SchedulingLane::Prefetch => Some(SchedulingLane::Writeback),
            SchedulingLane::Maintenance => Some(SchedulingLane::Prefetch),
            SchedulingLane::Idle => Some(SchedulingLane::Maintenance),
        }
    }
}

impl fmt::Display for SchedulingLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── Schedulable trait ────────────────────────────────────────────────

/// A unit of schedulable background work.
///
/// Callers implement this trait and submit items to the scheduler
/// via `BackgroundScheduler::submit()`. The scheduler calls `run()`
/// when the item reaches the front of its lane's FIFO queue and
/// budget is available.
pub trait Schedulable: Send {
    /// The lane this work item belongs to.
    fn lane(&self) -> SchedulingLane;

    /// Execute one unit of work. Called by the scheduler during `poll()`.
    ///
    /// Returns `Ok(())` if work was done (the item consumed budget).
    /// The scheduler uses `cost_hint()` to debit the lane budget.
    fn run(&mut self) -> Result<(), SchedulerWorkError>;

    /// Estimated cost in abstract tokens (items, records, or extent ops).
    ///
    /// The scheduler subtracts this from the lane's per-tick budget.
    /// A return of 0 means "no meaningful cost" — the item will not
    /// consume budget but will still be dispatched.
    fn cost_hint(&self) -> u64;
}

// ── Error type ───────────────────────────────────────────────────────

/// Errors produced during work-item execution.
#[derive(Clone, Debug)]
pub enum SchedulerWorkError {
    /// Work item failed with a message.
    Failed(&'static str),
    /// Work item was cancelled (shutdown, drain).
    Cancelled,
    /// Work item exceeded its own internal budget.
    OverBudget { limit: u64, actual: u64 },
}

impl fmt::Display for SchedulerWorkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SchedulerWorkError::Failed(msg) => write!(f, "work item failed: {msg}"),
            SchedulerWorkError::Cancelled => write!(f, "work item cancelled"),
            SchedulerWorkError::OverBudget { limit, actual } => {
                write!(f, "work item over budget (limit={limit}, actual={actual})")
            }
        }
    }
}

// ── PollResult ───────────────────────────────────────────────────────

/// Outcome of a `poll()` call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PollResult {
    /// One or more work items were processed.
    WorkDone {
        /// Number of items successfully processed.
        items_processed: u64,
        /// Number of items that failed.
        items_failed: u64,
        /// Number of items that were bumped to a higher lane
        /// due to starvation prevention.
        items_promoted: u64,
        /// True if more work remains queued.
        has_more: bool,
    },
    /// No work items in any lane.
    Idle,
    /// Budget exhausted before all work could be processed.
    BudgetExhausted,
}

impl PollResult {
    /// Total items affected this poll (processed + failed + promoted).
    #[must_use]
    pub fn total_items(&self) -> u64 {
        match self {
            PollResult::WorkDone {
                items_processed,
                items_failed,
                items_promoted,
                ..
            } => items_processed + items_failed + items_promoted,
            PollResult::Idle | PollResult::BudgetExhausted => 0,
        }
    }
}

impl fmt::Display for PollResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PollResult::WorkDone {
                items_processed,
                items_failed,
                items_promoted,
                has_more,
            } => {
                write!(
                    f,
                    "work_done processed={items_processed} failed={items_failed} promoted={items_promoted} has_more={has_more}"
                )
            }
            PollResult::Idle => write!(f, "idle"),
            PollResult::BudgetExhausted => write!(f, "budget_exhausted"),
        }
    }
}

// ── LaneBudget ───────────────────────────────────────────────────────

/// Per-tick budget allocated to a single lane.
///
/// The budget is expressed in abstract tokens (the unit of
/// `Schedulable::cost_hint()`). A budget of `0` means unbounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneBudget {
    /// Maximum token cost this lane can consume per poll.
    /// 0 = unbounded.
    pub max_cost: u64,
}

impl LaneBudget {
    /// Create a bounded budget.
    #[must_use]
    pub const fn new(max_cost: u64) -> Self {
        Self { max_cost }
    }

    /// Unbounded budget.
    pub const UNBOUNDED: Self = Self { max_cost: 0 };
}

impl Default for LaneBudget {
    fn default() -> Self {
        Self::UNBOUNDED
    }
}

// ── StarvationConfig ─────────────────────────────────────────────────

/// Configuration for starvation prevention.
///
/// When a work item has been queued longer than `threshold_ms` in its
/// current lane, it is promoted to the next higher lane (if any).
#[derive(Clone, Copy, Debug)]
pub struct StarvationConfig {
    /// Time in milliseconds after which an item is considered starved.
    /// 0 = disabled (no starvation promotion).
    pub threshold_ms: u64,
}

impl StarvationConfig {
    /// Disabled: items are never promoted due to starvation.
    pub const DISABLED: Self = Self { threshold_ms: 0 };

    /// Default: promote after 500ms.
    pub const DEFAULT: Self = Self { threshold_ms: 500 };
}

impl Default for StarvationConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

// ── QueuedWorkItem ───────────────────────────────────────────────────

/// A work item in a lane queue, annotated with its enqueue time.
struct QueuedWorkItem {
    /// The schedulable work.
    item: Box<dyn Schedulable>,
    /// Monotonic timestamp (ms) when this item was enqueued.
    queued_at_ms: u64,
    /// Original lane at enqueue time (for observability).
    original_lane: SchedulingLane,
    /// True if this item was promoted during the current tick (avoids cascading).
    promoted_this_tick: bool,
}

impl fmt::Debug for QueuedWorkItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QueuedWorkItem")
            .field("lane", &self.item.lane())
            .field("cost", &self.item.cost_hint())
            .field("queued_at_ms", &self.queued_at_ms)
            .field("original_lane", &self.original_lane)
            .finish()
    }
}

// ── Observability types ──────────────────────────────────────────────

/// Per-lane depth counters exposed when `observability` feature is active.
#[cfg(feature = "observability")]
#[derive(Clone, Debug, Default)]
pub struct LaneDepthCounters {
    /// Current queue depth per lane.
    pub depths: [u64; SchedulingLane::LANE_COUNT],
    /// Cumulative items submitted per lane since last reset.
    pub submitted: [u64; SchedulingLane::LANE_COUNT],
    /// Cumulative items processed per lane since last reset.
    pub processed: [u64; SchedulingLane::LANE_COUNT],
    /// Cumulative items promoted (starvation) per lane since last reset.
    pub promoted: [u64; SchedulingLane::LANE_COUNT],
}

#[cfg(feature = "observability")]
impl LaneDepthCounters {
    /// Create empty counters.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset all counters to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// Per-lane wait-time histogram.
///
/// Tracks how long items waited before being dispatched.
/// Buckets: <10ms, <50ms, <100ms, <500ms, <1s, <5s, <30s, >=30s.
#[cfg(feature = "observability")]
#[derive(Clone, Debug)]
pub struct WaitTimeHistogram {
    /// Histogram counts per lane, 8 buckets per lane.
    /// Layout: [lane0_bucket0..lane0_bucket7, lane1_bucket0.., ...]
    pub buckets: [u64; SchedulingLane::LANE_COUNT * 8],
}

#[cfg(feature = "observability")]
impl Default for WaitTimeHistogram {
    fn default() -> Self {
        Self {
            buckets: [0u64; SchedulingLane::LANE_COUNT * 8],
        }
    }
}

#[cfg(feature = "observability")]
impl WaitTimeHistogram {
    /// Bucket boundaries in milliseconds.
    const BOUNDARIES: [u64; 7] = [10, 50, 100, 500, 1_000, 5_000, 30_000];

    /// Create an empty histogram.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a wait time for a lane.
    pub fn record(&mut self, lane: SchedulingLane, wait_ms: u64) {
        let base = lane as usize * 8;
        let bucket = Self::BOUNDARIES
            .iter()
            .position(|&b| wait_ms < b)
            .unwrap_or(Self::BOUNDARIES.len());
        self.buckets[base + bucket] = self.buckets[base + bucket].saturating_add(1);
    }

    /// Reset all buckets to zero.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

// ── WorkItemQueue ────────────────────────────────────────────────────

/// Per-lane FIFO work queues with budget tracking and starvation prevention.
///
/// This is the core dispatch engine behind `BackgroundScheduler::poll()`.
/// It holds five `VecDeque<QueuedWorkItem>` (one per lane), tracks per-lane
/// budget consumption, and promotes starved items to higher lanes.
#[cfg(feature = "alloc")]
pub(crate) struct WorkItemQueue {
    /// One FIFO queue per lane.
    lanes: [VecDeque<QueuedWorkItem>; SchedulingLane::LANE_COUNT],
    /// Per-lane budget (tokens remaining this poll cycle).
    lane_budget_remaining: [u64; SchedulingLane::LANE_COUNT],
    /// Per-lane budget caps (reset each poll).
    lane_budgets: [LaneBudget; SchedulingLane::LANE_COUNT],
    /// Starvation configuration.
    starve: StarvationConfig,
    /// Current time source (ms). Updated before each poll cycle.
    now_ms: u64,
    /// Total items submitted (for observability, always tracked).
    total_submitted: u64,
    /// Total items processed (for observability, always tracked).
    total_processed: u64,
    /// Total items promoted (for observability, always tracked).
    total_promoted: u64,
    /// Observability: lane-depth counters.
    #[cfg(feature = "observability")]
    depth_counters: LaneDepthCounters,
    /// Observability: wait-time histogram.
    #[cfg(feature = "observability")]
    wait_histogram: WaitTimeHistogram,
}

#[cfg(feature = "alloc")]
#[allow(dead_code)]
impl WorkItemQueue {
    /// Create an empty work queue with per-lane budgets and starvation
    /// config.
    #[must_use]
    pub fn new(
        lane_budgets: [LaneBudget; SchedulingLane::LANE_COUNT],
        starve: StarvationConfig,
    ) -> Self {
        Self {
            lanes: [
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
                VecDeque::new(),
            ],
            lane_budget_remaining: lane_budgets.map(|b| b.max_cost),
            lane_budgets,
            starve,
            now_ms: 0,
            total_submitted: 0,
            total_processed: 0,
            total_promoted: 0,
            #[cfg(feature = "observability")]
            depth_counters: LaneDepthCounters::new(),
            #[cfg(feature = "observability")]
            wait_histogram: WaitTimeHistogram::new(),
        }
    }

    /// Create a queue with uniform unbounded budgets and default
    /// starvation.
    #[must_use]
    pub fn new_default() -> Self {
        Self::new(
            [LaneBudget::UNBOUNDED; SchedulingLane::LANE_COUNT],
            StarvationConfig::default(),
        )
    }

    /// Set the current time (call before `poll()`).
    pub fn set_now_ms(&mut self, now_ms: u64) {
        self.now_ms = now_ms;
    }

    /// Submit a work item into its lane.
    pub fn submit(&mut self, item: Box<dyn Schedulable>) {
        let lane = item.lane();
        let qi = QueuedWorkItem {
            original_lane: lane,
            queued_at_ms: self.now_ms,
            item,
            promoted_this_tick: false,
        };
        self.lanes[lane as usize].push_back(qi);
        self.total_submitted = self.total_submitted.saturating_add(1);

        #[cfg(feature = "observability")]
        {
            self.depth_counters.submitted[lane as usize] =
                self.depth_counters.submitted[lane as usize].saturating_add(1);
        }
    }

    /// Total number of items across all lanes.
    #[must_use]
    pub fn total_queued(&self) -> usize {
        self.lanes.iter().map(|q| q.len()).sum()
    }

    /// Depth of a specific lane.
    #[must_use]
    pub fn lane_depth(&self, lane: SchedulingLane) -> usize {
        self.lanes[lane as usize].len()
    }

    /// True if no items are queued in any lane.
    #[must_use]
    pub fn is_idle(&self) -> bool {
        self.lanes.iter().all(|q| q.is_empty())
    }

    /// Promote starved items: each lane's front item is promoted at most
    /// one level per poll to avoid cascading an item through all lanes
    /// in a single tick.
    fn promote_starved(&mut self) -> u64 {
        if self.starve.threshold_ms == 0 {
            return 0;
        }

        let mut promoted = 0u64;

        // Walk lanes from lowest to highest (Idle..Writeback).
        // Critical (lane 0) cannot be promoted from.
        for lane_idx in (1..SchedulingLane::LANE_COUNT).rev() {
            if self.lanes[lane_idx].is_empty() {
                continue;
            }

            let front = self.lanes[lane_idx].front().unwrap();
            // Skip items already promoted this tick to avoid cascading.
            if front.promoted_this_tick {
                continue;
            }
            let wait_ms = self.now_ms.saturating_sub(front.queued_at_ms);
            if wait_ms >= self.starve.threshold_ms {
                // Pop from current lane and push to next higher lane.
                let mut qi = self.lanes[lane_idx].pop_front().unwrap();
                let target_lane = lane_idx - 1; // next higher priority
                qi.item = Box::new(PromotedItem {
                    inner: qi.item,
                    new_lane: SchedulingLane::ALL[target_lane],
                });
                self.lanes[target_lane].push_back(qi);
                // Mark the newly pushed item to avoid re-promotion this tick.
                self.lanes[target_lane]
                    .back_mut()
                    .unwrap()
                    .promoted_this_tick = true;
                promoted += 1;

                #[cfg(feature = "observability")]
                {
                    let from_lane = SchedulingLane::ALL[lane_idx];
                    self.depth_counters.promoted[from_lane as usize] =
                        self.depth_counters.promoted[from_lane as usize].saturating_add(1);
                }
            }
        }

        self.total_promoted = self.total_promoted.saturating_add(promoted);
        promoted
    }

    /// Poll one scheduling tick.
    ///
    /// Drains lanes in priority order (Critical → Idle). For each lane,
    /// pops items from the front and calls `run()` until the lane budget
    /// is exhausted or the lane queue is empty.
    ///
    /// Returns `PollResult` indicating work done, idle, or budget
    /// exhausted.
    pub fn poll(&mut self) -> PollResult {
        // Step 1: promote starved items.
        let promoted = self.promote_starved();

        // Step 2: reset lane budgets for this tick.
        self.lane_budget_remaining = self.lane_budgets.map(|b| b.max_cost);

        let mut total_processed = 0u64;
        let mut total_failed = 0u64;
        let mut any_work = false;

        // Step 3: drain lanes in priority order.
        for lane in &SchedulingLane::ALL {
            let lane_idx = *lane as usize;
            let lane_budget_cap = self.lane_budgets[lane_idx].max_cost;
            let lane_idx = *lane as usize;
            loop {
                if self.lanes[lane_idx].is_empty() {
                    break;
                }

                // Check if lane budget is exhausted.
                // Unbounded lanes (cap == 0) always continue.
                let budget_remaining = self.lane_budget_remaining[lane_idx];
                if lane_budget_cap > 0 && budget_remaining == 0 {
                    break;
                }

                // Peek at the front item's cost hint.
                let cost = {
                    let front = self.lanes[lane_idx].front().unwrap();
                    front.item.cost_hint()
                };

                // If bounded and cost exceeds remaining budget, skip
                // this lane and mark budget exhausted.
                if lane_budget_cap > 0 && cost > budget_remaining {
                    break;
                }

                // Pop and run the item.
                let mut qi = self.lanes[lane_idx].pop_front().unwrap();
                #[cfg(feature = "observability")]
                {
                    let wait_ms = self.now_ms.saturating_sub(qi.queued_at_ms);
                    self.wait_histogram.record(*lane, wait_ms);
                }

                match qi.item.run() {
                    Ok(()) => {
                        total_processed += 1;
                        any_work = true;
                    }
                    Err(_) => {
                        total_failed += 1;
                        any_work = true;
                    }
                }

                // Debit lane budget (only for bounded lanes).
                if lane_budget_cap > 0 {
                    self.lane_budget_remaining[lane_idx] =
                        self.lane_budget_remaining[lane_idx].saturating_sub(cost);
                }
            }
        }

        self.total_processed = self.total_processed.saturating_add(total_processed);

        #[cfg(feature = "observability")]
        {
            for (i, _lane) in SchedulingLane::ALL.iter().enumerate() {
                self.depth_counters.depths[i] = self.lanes[i].len() as u64;
                self.depth_counters.processed[i] =
                    self.depth_counters.processed[i].saturating_add(total_processed);
            }
        }

        if any_work || promoted > 0 {
            PollResult::WorkDone {
                items_processed: total_processed,
                items_failed: total_failed,
                items_promoted: promoted,
                has_more: self.total_queued() > 0,
            }
        } else if self.total_queued() == 0 {
            PollResult::Idle
        } else {
            PollResult::BudgetExhausted
        }
    }

    /// Access lane-depth counters (always available, gated fields zero
    /// when feature is off).
    #[cfg(feature = "observability")]
    #[must_use]
    pub fn depth_counters(&self) -> &LaneDepthCounters {
        &self.depth_counters
    }

    /// Access wait-time histogram.
    #[cfg(feature = "observability")]
    #[must_use]
    pub fn wait_histogram(&self) -> &WaitTimeHistogram {
        &self.wait_histogram
    }

    /// Total items ever submitted.
    #[must_use]
    pub fn total_submitted(&self) -> u64 {
        self.total_submitted
    }

    /// Total items ever processed.
    #[must_use]
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }

    /// Total items ever promoted due to starvation.
    #[must_use]
    pub fn total_promoted(&self) -> u64 {
        self.total_promoted
    }
}

// ── PromotedItem wrapper ─────────────────────────────────────────────

/// Wrapper that overrides the lane of an inner `Schedulable`.
///
/// Used by starvation promotion: the item is moved to a higher lane
/// queue, but its `run()` and `cost_hint()` still delegate to the
/// original implementation.
struct PromotedItem {
    inner: Box<dyn Schedulable>,
    new_lane: SchedulingLane,
}

impl Schedulable for PromotedItem {
    fn lane(&self) -> SchedulingLane {
        self.new_lane
    }

    fn run(&mut self) -> Result<(), SchedulerWorkError> {
        self.inner.run()
    }

    fn cost_hint(&self) -> u64 {
        self.inner.cost_hint()
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;

    // ── MockWorkItem ───────────────────────────────────────────────

    /// A test work item with controllable lane, cost, and success.
    struct MockWorkItem {
        lane: SchedulingLane,
        cost: u64,
        should_fail: bool,
        run_count: std::cell::Cell<u32>,
    }

    impl MockWorkItem {
        fn new(lane: SchedulingLane, cost: u64) -> Self {
            Self {
                lane,
                cost,
                should_fail: false,
                run_count: std::cell::Cell::new(0),
            }
        }

        fn failing(mut self) -> Self {
            self.should_fail = true;
            self
        }
    }

    impl Schedulable for MockWorkItem {
        fn lane(&self) -> SchedulingLane {
            self.lane
        }

        fn run(&mut self) -> Result<(), SchedulerWorkError> {
            self.run_count.set(self.run_count.get() + 1);
            if self.should_fail {
                Err(SchedulerWorkError::Failed("mock failure"))
            } else {
                Ok(())
            }
        }

        fn cost_hint(&self) -> u64 {
            self.cost
        }
    }

    // ── Lane tests ─────────────────────────────────────────────────

    #[test]
    fn lane_ordering() {
        assert!(SchedulingLane::Critical < SchedulingLane::Writeback);
        assert!(SchedulingLane::Writeback < SchedulingLane::Prefetch);
        assert!(SchedulingLane::Prefetch < SchedulingLane::Maintenance);
        assert!(SchedulingLane::Maintenance < SchedulingLane::Idle);
    }

    #[test]
    fn lane_promote_chain() {
        assert_eq!(
            SchedulingLane::Idle.promote(),
            Some(SchedulingLane::Maintenance)
        );
        assert_eq!(
            SchedulingLane::Maintenance.promote(),
            Some(SchedulingLane::Prefetch)
        );
        assert_eq!(
            SchedulingLane::Prefetch.promote(),
            Some(SchedulingLane::Writeback)
        );
        assert_eq!(
            SchedulingLane::Writeback.promote(),
            Some(SchedulingLane::Critical)
        );
        assert_eq!(SchedulingLane::Critical.promote(), None);
    }

    #[test]
    fn all_lanes_covers_five_levels() {
        assert_eq!(SchedulingLane::ALL.len(), 5);
    }

    #[test]
    fn lane_labels_nonempty() {
        for l in &SchedulingLane::ALL {
            assert!(!l.label().is_empty());
        }
    }

    // ── WorkItemQueue tests ────────────────────────────────────────

    #[test]
    fn empty_queue_poll_returns_idle() {
        let mut q = WorkItemQueue::new_default();
        assert!(q.is_idle());
        assert_eq!(q.poll(), PollResult::Idle);
    }

    #[test]
    fn single_item_poll_processes_it() {
        let mut q = WorkItemQueue::new_default();
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Writeback, 1)));
        assert!(!q.is_idle());
        let result = q.poll();
        assert_eq!(
            result,
            PollResult::WorkDone {
                items_processed: 1,
                items_failed: 0,
                items_promoted: 0,
                has_more: false,
            }
        );
        assert!(q.is_idle());
    }

    #[test]
    fn multiple_items_across_lanes_priority_order() {
        let mut q = WorkItemQueue::new(
            [LaneBudget::UNBOUNDED; SchedulingLane::LANE_COUNT],
            StarvationConfig::DISABLED,
        );

        // Submit Idle first, then Critical. Critical should run first
        // but both run in one poll (unbounded budgets).
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));

        let result = q.poll();
        assert_eq!(
            result,
            PollResult::WorkDone {
                items_processed: 2,
                items_failed: 0,
                items_promoted: 0,
                has_more: false,
            }
        );
    }

    #[test]
    fn budget_exhaustion_limits_dispatch() {
        // Critical gets budget of 2 tokens; other lanes unbounded.
        let mut q = WorkItemQueue::new(
            [
                LaneBudget::new(2),    // Critical
                LaneBudget::UNBOUNDED, // Writeback
                LaneBudget::UNBOUNDED, // Prefetch
                LaneBudget::UNBOUNDED, // Maintenance
                LaneBudget::UNBOUNDED, // Idle
            ],
            StarvationConfig::DISABLED,
        );

        // Submit 3 Critical items each costing 1.
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));

        let result = q.poll();
        // 2 processed (budget of 2), 1 left. Budget remaining 0
        // so lane exhausted. WorkDone because items were processed.
        assert_eq!(
            result,
            PollResult::WorkDone {
                items_processed: 2,
                items_failed: 0,
                items_promoted: 0,
                has_more: true,
            }
        );
        assert_eq!(q.lane_depth(SchedulingLane::Critical), 1);
        assert_eq!(q.total_processed(), 2);
    }

    #[test]
    fn budget_resets_per_poll() {
        let mut q = WorkItemQueue::new(
            [LaneBudget::new(1); SchedulingLane::LANE_COUNT],
            StarvationConfig::DISABLED,
        );

        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));

        // First poll: one processed, one remains.
        let r1 = q.poll();
        assert_eq!(r1.total_items(), 1);
        assert_eq!(q.lane_depth(SchedulingLane::Critical), 1);

        // Second poll: budget resets, remaining item processed.
        let r2 = q.poll();
        assert_eq!(r2.total_items(), 1);
        assert!(q.is_idle());
    }

    #[test]
    fn higher_lane_drains_before_lower() {
        let mut q = WorkItemQueue::new_default();

        // Submit items to all lanes.
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Maintenance, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Prefetch, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Writeback, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));

        // All get processed in one poll (unbounded budgets).
        let result = q.poll();
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
    fn failed_item_counts_as_work() {
        let mut q = WorkItemQueue::new_default();
        q.submit(Box::new(
            MockWorkItem::new(SchedulingLane::Critical, 1).failing(),
        ));

        let result = q.poll();
        assert_eq!(
            result,
            PollResult::WorkDone {
                items_processed: 0,
                items_failed: 1,
                items_promoted: 0,
                has_more: false,
            }
        );
    }

    #[test]
    fn zero_cost_item_always_dispatched() {
        // Bounded budget of 1 token, but items with cost 0 don't
        // consume budget.
        let mut q = WorkItemQueue::new(
            [LaneBudget::new(1); SchedulingLane::LANE_COUNT],
            StarvationConfig::DISABLED,
        );

        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 0)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 0)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 0)));

        // All three should process: cost_hint=0 never exhausts budget
        // (budget subtraction is a no-op for 0 cost).
        let result = q.poll();
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

    // ── Starvation prevention tests ────────────────────────────────

    #[test]
    fn starvation_promotes_item_after_threshold() {
        let mut q = WorkItemQueue::new(
            [LaneBudget::UNBOUNDED; SchedulingLane::LANE_COUNT],
            StarvationConfig { threshold_ms: 100 },
        );

        // Submit an Idle item at t=0.
        q.set_now_ms(0);
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));

        // Advance time past threshold.
        q.set_now_ms(150);

        // Poll: item should be promoted one level, then run.
        let result = q.poll();
        assert_eq!(
            result,
            PollResult::WorkDone {
                items_processed: 1,
                items_failed: 0,
                items_promoted: 1,
                has_more: false,
            }
        );
        assert_eq!(q.total_promoted(), 1);
    }

    #[test]
    fn starvation_disabled_when_threshold_zero() {
        let mut q = WorkItemQueue::new(
            [LaneBudget::UNBOUNDED; SchedulingLane::LANE_COUNT],
            StarvationConfig::DISABLED,
        );

        q.set_now_ms(0);
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));
        q.set_now_ms(9999);

        let result = q.poll();
        assert_eq!(result.total_items(), 1);
        match result {
            PollResult::WorkDone { items_promoted, .. } => {
                assert_eq!(items_promoted, 0);
            }
            _ => panic!("expected WorkDone"),
        }
    }

    #[test]
    fn starvation_does_not_promote_before_threshold() {
        let mut q = WorkItemQueue::new(
            [LaneBudget::UNBOUNDED; SchedulingLane::LANE_COUNT],
            StarvationConfig { threshold_ms: 100 },
        );

        q.set_now_ms(0);
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));
        q.set_now_ms(50); // below threshold

        let result = q.poll();
        match result {
            PollResult::WorkDone { items_promoted, .. } => {
                assert_eq!(items_promoted, 0);
            }
            _ => panic!("expected WorkDone"),
        }
    }

    #[test]
    fn promoted_item_runs_in_higher_lane() {
        let mut q = WorkItemQueue::new(
            [
                LaneBudget::new(1),    // Critical
                LaneBudget::UNBOUNDED, // Writeback
                LaneBudget::UNBOUNDED, // Prefetch
                LaneBudget::UNBOUNDED, // Maintenance
                LaneBudget::UNBOUNDED, // Idle
            ],
            StarvationConfig { threshold_ms: 50 },
        );

        // Submit an Idle item (will starve) and a Critical item.
        q.set_now_ms(0);
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));

        q.set_now_ms(100);

        let _ = q.poll();
        // Critical lane: 1 item processed (consumes budget).
        // Starved Idle item promoted to Maintenance, runs (unbounded).
        assert_eq!(q.total_processed(), 2);
        assert!(q.is_idle());
    }

    // ── Deterministic simulation test ──────────────────────────────

    #[test]
    fn deterministic_simulation_known_sequence() {
        // Submit a fixed sequence, advance tick-by-tick, assert exact
        // dispatch counts.
        let mut q = WorkItemQueue::new(
            [
                LaneBudget::new(2),    // Critical: 2 tokens
                LaneBudget::new(2),    // Writeback: 2 tokens
                LaneBudget::new(1),    // Prefetch: 1 token
                LaneBudget::UNBOUNDED, // Maintenance: unbounded
                LaneBudget::UNBOUNDED, // Idle: unbounded
            ],
            StarvationConfig::DISABLED,
        );

        q.set_now_ms(0);

        // Critical: items A(cost=1), B(cost=2)
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 2)));
        // Writeback: items C(cost=1), D(cost=1)
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Writeback, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Writeback, 1)));
        // Prefetch: item E(cost=2) — exceeds Prefetch budget of 1
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Prefetch, 2)));
        // Maintenance: item F(cost=5) — unbounded
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Maintenance, 5)));

        // Tick 1:
        // Critical: C1(cost=1) ok, C2(cost=2) > remaining 1 → skip
        // Writeback: W1(cost=1) ok, W2(cost=1) ok (budget 2-1-1=0)
        // Prefetch: P1(cost=2) > budget 1 → skip, mark budget exhausted
        // Maintenance: M1 unbounded → runs
        let r1 = q.poll();
        assert_eq!(r1.total_items(), 4); // C1, W1, W2, M1
        assert_eq!(q.lane_depth(SchedulingLane::Critical), 1); // C2
        assert_eq!(q.lane_depth(SchedulingLane::Prefetch), 1); // P1

        // Tick 2: budgets reset.
        // Critical: C2(cost=2) → budget 2-2=0, runs.
        // Prefetch: P1(cost=2) > budget 1 → skip, mark exhausted.
        let r2 = q.poll();
        assert_eq!(r2.total_items(), 1); // C2
        assert_eq!(q.lane_depth(SchedulingLane::Prefetch), 1);

        // Tick 3: Prefetch budget resets. P1(cost=2) still > budget 1.
        let r3 = q.poll();
        assert_eq!(r3, PollResult::BudgetExhausted);
        assert_eq!(q.lane_depth(SchedulingLane::Prefetch), 1);
    }

    #[test]
    fn cost_hint_accounting_prevents_over_dispatch() {
        // Budget of 10, items costing 4 each → only 2 dispatched per
        // poll.
        let mut q = WorkItemQueue::new(
            [LaneBudget::new(10); SchedulingLane::LANE_COUNT],
            StarvationConfig::DISABLED,
        );

        for _ in 0..5 {
            q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 4)));
        }

        // Tick 1: items with cost 4,4 → budget 10-4-4=2, third 4 > 2.
        let r1 = q.poll();
        assert_eq!(r1.total_items(), 2);
        assert_eq!(q.lane_depth(SchedulingLane::Critical), 3);

        // Tick 2: budget resets, 2 more.
        let r2 = q.poll();
        assert_eq!(r2.total_items(), 2);
        assert_eq!(q.lane_depth(SchedulingLane::Critical), 1);

        // Tick 3: last item.
        let r3 = q.poll();
        assert_eq!(r3.total_items(), 1);
        assert!(q.is_idle());
    }

    // ── Observability tests ────────────────────────────────────────

    #[cfg(feature = "observability")]
    #[test]
    fn depth_counters_track_submissions() {
        let mut q = WorkItemQueue::new_default();
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Writeback, 1)));
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Idle, 1)));

        let dc = q.depth_counters();
        assert_eq!(dc.submitted[SchedulingLane::Critical as usize], 1);
        assert_eq!(dc.submitted[SchedulingLane::Writeback as usize], 1);
        assert_eq!(dc.submitted[SchedulingLane::Idle as usize], 1);
        assert_eq!(dc.submitted[SchedulingLane::Prefetch as usize], 0);
    }

    #[cfg(feature = "observability")]
    #[test]
    fn depth_counters_reset() {
        let mut q = WorkItemQueue::new_default();
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.poll();
        let mut dc = q.depth_counters().clone();
        dc.reset();
        assert_eq!(dc.submitted[SchedulingLane::Critical as usize], 0);
    }

    #[cfg(feature = "observability")]
    #[test]
    fn wait_histogram_records() {
        let mut q = WorkItemQueue::new_default();
        q.set_now_ms(0);
        q.submit(Box::new(MockWorkItem::new(SchedulingLane::Critical, 1)));
        q.set_now_ms(75); // 75ms wait → <100ms bucket
        q.poll();

        let wh = q.wait_histogram();
        let base = SchedulingLane::Critical as usize * 8;
        // Buckets: 0<10ms, 1<50ms, 2<100ms, 3<500ms, ...
        assert_eq!(wh.buckets[base + 2], 1);
    }

    // ── Display tests ──────────────────────────────────────────────

    #[test]
    fn poll_result_display_nonempty() {
        let results = [
            PollResult::WorkDone {
                items_processed: 3,
                items_failed: 1,
                items_promoted: 0,
                has_more: true,
            },
            PollResult::Idle,
            PollResult::BudgetExhausted,
        ];
        for r in &results {
            assert!(!format!("{r}").is_empty());
        }
    }

    #[test]
    fn scheduler_work_error_display_nonempty() {
        let errors = [
            SchedulerWorkError::Failed("test"),
            SchedulerWorkError::Cancelled,
            SchedulerWorkError::OverBudget {
                limit: 10,
                actual: 15,
            },
        ];
        for e in &errors {
            assert!(!format!("{e}").is_empty());
        }
    }

    #[test]
    fn scheduling_lane_display_nonempty() {
        for l in &SchedulingLane::ALL {
            assert!(!format!("{l}").is_empty());
        }
    }
}
