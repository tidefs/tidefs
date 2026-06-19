//! CleanupEngine: BLAKE3-verified deferred cleanup queue execution engine.
//!
//! The engine iterates the persistent [`CleanupQueue`], dispatches work
//! items to a [`JobExecutor`], records progress via [`CleanupProgress`],
//! and supports crash-safe resume from the last checkpointed entry ID.

use tidefs_cleanup_job_core::{CleanupContext, JobOutcome};
use tidefs_cleanup_queue_core::CleanupQueue;

use crate::job_executor::JobExecutor;
use crate::receipts::{
    CleanupReplayDecision, CleanupReplayDecisionReceipt, CleanupReplayRequiredEvidence,
    CleanupReplayValidationTier,
};
use std::fmt;

use crate::progress::CleanupProgress;

// ---------------------------------------------------------------------------
// EngineStats
// ---------------------------------------------------------------------------

/// Accumulated statistics for a cleanup engine run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EngineStats {
    /// Total work items processed (dispatched to executor).
    pub items_processed: u64,
    /// Items marked complete by the executor.
    pub items_completed: u64,
    /// Items that returned `Incomplete` (more work needed in next epoch).
    pub items_incomplete: u64,
    /// Items that returned `Retryable` (transient failure).
    pub items_retryable: u64,
    /// Items that returned `Fatal` (unrecoverable failure).
    pub items_fatal: u64,
    /// If true, the engine has exhausted the queue.
    pub queue_exhausted: bool,
}

impl EngineStats {
    /// Zero-valued statistics.
    pub const ZERO: Self = Self {
        items_processed: 0,
        items_completed: 0,
        items_incomplete: 0,
        items_retryable: 0,
        items_fatal: 0,
        queue_exhausted: false,
    };
}

// ---
// ---------------------------------------------------------------------------
// CleanupEngineState
// ---------------------------------------------------------------------------

/// Operational state of the cleanup engine.
///
/// The engine transitions through three states:
/// - **Idle**: Not processing. start() -> Running.
/// - **Running**: Actively processing. drain() -> Draining.
/// - **Draining**: Finishing current batch. Auto-transitions to Idle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupEngineState {
    Idle,
    Running,
    Draining,
}

impl CleanupEngineState {
    #[must_use]
    pub fn can_process(self) -> bool {
        matches!(self, Self::Running | Self::Draining)
    }
    #[must_use]
    pub fn is_idle(self) -> bool {
        matches!(self, Self::Idle)
    }
}

impl fmt::Display for CleanupEngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Running => f.write_str("Running"),
            Self::Draining => f.write_str("Draining"),
        }
    }
}

/// Errors returned by state transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StateTransitionError {
    InvalidTransition {
        from: CleanupEngineState,
        to: CleanupEngineState,
    },
    NotExhausted {
        pending: usize,
    },
}

impl fmt::Display for StateTransitionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition from {from} to {to}")
            }
            Self::NotExhausted { pending } => write!(f, "cannot stop: {pending} items pending"),
        }
    }
}

impl std::error::Error for StateTransitionError {}

// ---------------------------------------------------------------------------
// CleanupEngine
// ---------------------------------------------------------------------------

/// Executes deferred cleanup work items from a persistent [`CleanupQueue`].
///
/// # Lifecycle
///
/// 1. Create with `new()` (or `resume()` with a prior progress blob).
/// 2. Call `run_cycle()` to process a batch of work items.
/// 3. Call `seal_progress()` to produce a BLAKE3-verified checkpoint blob.
/// 4. After a crash, call `resume()` with the saved blob to skip
///    already-processed items.
///
/// # Batch semantics
///
/// `run_cycle()` processes up to `batch_size` pending work items. Items
/// already marked complete are skipped. Items before the progress cursor
/// are skipped (resume safety). After each batch the progress cursor is
/// advanced past the last item processed with a terminal outcome.
///
/// # Crash safety
///
/// The engine does not commit to the intent log itself; the caller is
/// responsible for persisting the progress blob alongside a TXG commit.
/// On crash, `resume()` with the last persisted blob restores the cursor
/// position, and the engine skips all items up to and including the
/// recorded `last_processed_entry_id`.
pub struct CleanupEngine<E: JobExecutor> {
    queue: CleanupQueue,
    /// Current operational state.
    state: CleanupEngineState,
    /// When Draining, max items before stopping.
    drain_budget: usize,
    executor: E,
    batch_size: usize,
    progress: CleanupProgress,
    stats: EngineStats,
    /// Entry IDs that were retried or left incomplete; they will be
    /// re-attempted in future cycles rather than skipped.
    retry_ids: Vec<u64>,
    /// Per-entry replay decisions observed by this engine instance.
    replay_decision_receipts: Vec<CleanupReplayDecisionReceipt>,
}

impl<E: JobExecutor> fmt::Debug for CleanupEngine<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CleanupEngine")
            .field("state", &self.state)
            .field("stats", &self.stats)
            .field("batch_size", &self.batch_size)
            .field("progress", &self.progress)
            .field("retry_ids", &self.retry_ids.len())
            .field(
                "replay_decision_receipts",
                &self.replay_decision_receipts.len(),
            )
            .finish_non_exhaustive()
    }
}

impl<E: JobExecutor> CleanupEngine<E> {
    /// Create a new engine from scratch.
    ///
    /// `batch_size` controls the maximum number of work items processed
    /// per `run_cycle()` call. A value of 0 means "no limit" (process all).
    pub fn new(queue: CleanupQueue, executor: E, batch_size: usize) -> Self {
        Self {
            state: CleanupEngineState::Idle,
            drain_budget: 0,
            queue,
            executor,
            batch_size,
            progress: CleanupProgress::new(),
            stats: EngineStats::ZERO,
            retry_ids: Vec::new(),
            replay_decision_receipts: Vec::new(),
        }
    }

    /// Resume from a previously persisted progress blob.
    ///
    /// All items up to and including the recorded `last_processed_entry_id`
    /// are skipped, unless they appear in the retry list.
    pub fn resume(
        queue: CleanupQueue,
        executor: E,
        batch_size: usize,
        progress_blob: &[u8],
    ) -> Result<Self, crate::progress::ProgressError> {
        let progress = CleanupProgress::from_sealed_blob(progress_blob)?;
        Ok(Self {
            state: CleanupEngineState::Idle,
            drain_budget: 0,
            queue,
            executor,
            batch_size,
            progress,
            stats: EngineStats::ZERO,
            retry_ids: Vec::new(),
            replay_decision_receipts: Vec::new(),
        })
    }

    /// Current engine state.
    #[must_use]
    pub fn state(&self) -> CleanupEngineState {
        self.state
    }

    /// Start processing. Idle -> Running.
    pub fn start(&mut self) -> Result<(), StateTransitionError> {
        if self.state != CleanupEngineState::Idle {
            return Err(StateTransitionError::InvalidTransition {
                from: self.state,
                to: CleanupEngineState::Running,
            });
        }
        self.state = CleanupEngineState::Running;
        Ok(())
    }

    /// Request drain: finish current work then stop. Running -> Draining.
    pub fn drain(&mut self, drain_after_batch: Option<usize>) -> Result<(), StateTransitionError> {
        if self.state != CleanupEngineState::Running {
            return Err(StateTransitionError::InvalidTransition {
                from: self.state,
                to: CleanupEngineState::Draining,
            });
        }
        self.state = CleanupEngineState::Draining;
        self.drain_budget = drain_after_batch.unwrap_or(usize::MAX);
        Ok(())
    }

    /// Stop processing. Draining -> Idle.
    pub fn stop(&mut self) -> Result<(), StateTransitionError> {
        if self.state != CleanupEngineState::Draining {
            return Err(StateTransitionError::InvalidTransition {
                from: self.state,
                to: CleanupEngineState::Idle,
            });
        }
        if !self.stats.queue_exhausted {
            let pending = self.queue.pending_count();
            if pending > 0 {
                return Err(StateTransitionError::NotExhausted { pending });
            }
        }
        self.state = CleanupEngineState::Idle;
        self.drain_budget = 0;
        Ok(())
    }

    /// Force-stop: transition to Idle regardless of state.
    pub fn force_stop(&mut self) {
        self.state = CleanupEngineState::Idle;
        self.drain_budget = 0;
    }

    #[must_use]
    pub fn can_run(&self) -> bool {
        self.state.can_process()
    }

    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.state == CleanupEngineState::Draining
    }

    /// Current engine statistics since creation or last reset.
    #[must_use]
    pub fn stats(&self) -> EngineStats {
        self.stats
    }

    /// Reset statistics (does not reset progress cursor).
    pub fn reset_stats(&mut self) {
        self.stats = EngineStats::ZERO;
    }

    /// Reference to the underlying queue.
    #[must_use]
    pub fn queue(&self) -> &CleanupQueue {
        &self.queue
    }

    /// Mutable reference to the underlying queue.
    pub fn queue_mut(&mut self) -> &mut CleanupQueue {
        &mut self.queue
    }

    /// Seal the current progress into a BLAKE3-verified blob for persistence.
    #[must_use]
    pub fn seal_progress(&self) -> [u8; crate::progress::SEALED_BLOB_SIZE] {
        self.progress.seal()
    }

    /// Return the last processed entry ID (for debugging).
    #[must_use]
    pub fn last_processed_entry_id(&self) -> u64 {
        self.progress.last_processed_entry_id
    }

    /// Replay decision receipts recorded since engine creation or the last
    /// explicit clear/take call.
    #[must_use]
    pub fn replay_decision_receipts(&self) -> &[CleanupReplayDecisionReceipt] {
        &self.replay_decision_receipts
    }

    /// Clear accumulated replay decision receipts without changing engine
    /// progress or statistics.
    pub fn clear_replay_decision_receipts(&mut self) {
        self.replay_decision_receipts.clear();
    }

    /// Drain accumulated replay decision receipts for external persistence.
    pub fn take_replay_decision_receipts(&mut self) -> Vec<CleanupReplayDecisionReceipt> {
        std::mem::take(&mut self.replay_decision_receipts)
    }

    /// Process up to `batch_size` pending work items in one cycle.
    ///
    /// Returns `true` if the queue has been fully exhausted (no more
    /// pending items remain).
    ///
    /// Items with `entry_id <= progress.last_processed_entry_id` are
    /// skipped unless they are in the retry list.
    pub fn run_cycle(&mut self) -> bool {
        // Auto-start from Idle; explicit start() still available for
        // state-machine control. When the queue is empty, mark exhausted.
        if self.state == CleanupEngineState::Idle {
            if self.queue.is_empty() {
                self.stats.queue_exhausted = true;
                return true;
            }
            self.state = CleanupEngineState::Running;
        }

        let started_draining = self.state == CleanupEngineState::Draining;

        let entries: Vec<(u64, tidefs_types_deferred_cleanup_core::CleanupWorkItemV1)> =
            self.queue.entries();

        let mut effective_limit = if self.batch_size == 0 {
            entries.len()
        } else {
            self.batch_size
        };
        if started_draining && self.drain_budget > 0 {
            effective_limit = effective_limit.min(self.drain_budget);
        }

        let mut processed_this_cycle = 0usize;
        let mut last_processed_id = self.progress.last_processed_entry_id;

        for (entry_id, mut item) in entries {
            // Stop once we hit the batch limit
            if processed_this_cycle >= effective_limit {
                // When draining with budget, auto-transition to Idle
                if started_draining
                    && self.drain_budget > 0
                    && processed_this_cycle >= self.drain_budget
                {
                    self.state = CleanupEngineState::Idle;
                    self.drain_budget = 0;
                }
                break;
            }

            // Skip already-completed items
            if item.is_complete() {
                self.replay_decision_receipts
                    .push(CleanupReplayDecisionReceipt::for_item(
                        entry_id,
                        &item,
                        CleanupReplayDecision::Skipped,
                        CleanupReplayRequiredEvidence::QueueCompletionFlag,
                        "entry already marked complete in cleanup queue",
                        CleanupReplayValidationTier::QueueEntry,
                    ));
                // Still advance progress past completed items
                last_processed_id = entry_id;
                continue;
            }

            // Skip items at-or-before the progress cursor unless they're retries
            let is_retry = self.retry_ids.contains(&entry_id);
            if !is_retry && entry_id <= self.progress.last_processed_entry_id {
                self.replay_decision_receipts
                    .push(CleanupReplayDecisionReceipt::for_item(
                        entry_id,
                        &item,
                        CleanupReplayDecision::Skipped,
                        CleanupReplayRequiredEvidence::ProgressCursor,
                        format!(
                            "entry id {entry_id} covered by progress cursor {}",
                            self.progress.last_processed_entry_id
                        ),
                        CleanupReplayValidationTier::EngineState,
                    ));
                continue;
            }

            // Remove from retry list now that we're processing it
            if is_retry {
                self.retry_ids.retain(|id| *id != entry_id);
            }

            let ctx = CleanupContext::new(entry_id, 0);
            let executor_name = self.executor.name().to_string();
            let outcome = self.executor.execute(&mut item, &ctx);

            self.stats.items_processed = self.stats.items_processed.saturating_add(1);
            processed_this_cycle = processed_this_cycle.saturating_add(1);

            match outcome {
                JobOutcome::Completed => {
                    self.replay_decision_receipts
                        .push(CleanupReplayDecisionReceipt::for_item(
                            entry_id,
                            &item,
                            CleanupReplayDecision::Executed,
                            CleanupReplayRequiredEvidence::ExecutorCompleted,
                            format!("executor {executor_name} completed cleanup item"),
                            CleanupReplayValidationTier::ExecutorOutcome,
                        ));
                    self.stats.items_completed = self.stats.items_completed.saturating_add(1);
                    self.queue.mark_complete(entry_id);
                    last_processed_id = entry_id;
                }
                JobOutcome::Incomplete => {
                    self.replay_decision_receipts
                        .push(CleanupReplayDecisionReceipt::for_item(
                            entry_id,
                            &item,
                            CleanupReplayDecision::Deferred,
                            CleanupReplayRequiredEvidence::ExecutorIncomplete,
                            format!("executor {executor_name} left cleanup item incomplete"),
                            CleanupReplayValidationTier::ExecutorOutcome,
                        ));
                    self.stats.items_incomplete = self.stats.items_incomplete.saturating_add(1);
                    // Re-enqueue for next cycle
                    self.retry_ids.push(entry_id);
                    last_processed_id = entry_id;
                }
                JobOutcome::Retryable(err) => {
                    self.replay_decision_receipts
                        .push(CleanupReplayDecisionReceipt::for_item(
                            entry_id,
                            &item,
                            CleanupReplayDecision::Deferred,
                            CleanupReplayRequiredEvidence::ExecutorRetryable,
                            format!(
                                "executor {executor_name} returned retryable {:?}: {}",
                                err.phase, err.message
                            ),
                            CleanupReplayValidationTier::ExecutorOutcome,
                        ));
                    self.stats.items_retryable = self.stats.items_retryable.saturating_add(1);
                    self.retry_ids.push(entry_id);
                    last_processed_id = entry_id;
                }
                JobOutcome::Fatal(err) => {
                    self.replay_decision_receipts
                        .push(CleanupReplayDecisionReceipt::for_item(
                            entry_id,
                            &item,
                            CleanupReplayDecision::Rejected,
                            CleanupReplayRequiredEvidence::ExecutorFatal,
                            format!(
                                "executor {executor_name} returned fatal {:?}: {}",
                                err.phase, err.message
                            ),
                            CleanupReplayValidationTier::ExecutorOutcome,
                        ));
                    self.stats.items_fatal = self.stats.items_fatal.saturating_add(1);
                    // Mark complete to prevent blocking the queue
                    item.mark_complete();
                    self.queue.mark_complete(entry_id);
                    last_processed_id = entry_id;
                }
            }
        }

        self.progress.record(last_processed_id);

        // Check if queue is exhausted (no more pending items)
        let remaining_pending = self.queue.pending_count();
        self.stats.queue_exhausted = remaining_pending == 0;

        // Auto-transition to Idle when draining and queue exhausted
        if started_draining && self.stats.queue_exhausted {
            self.state = CleanupEngineState::Idle;
            self.drain_budget = 0;
        }

        self.stats.queue_exhausted
    }

    /// Run cycles until the queue is exhausted or the deadline is reached.
    ///
    /// `deadline` is a wall-clock timestamp in seconds since UNIX epoch.
    /// Returns `true` if the queue was fully exhausted, `false` if the
    /// deadline was hit first.
    pub fn run_with_deadline(&mut self, deadline_secs: u64) -> bool {
        loop {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now >= deadline_secs {
                return false;
            }

            let exhausted = self.run_cycle();
            if exhausted {
                return true;
            }
        }
    }

    /// Convenience entry point: run a single cleanup pass.
    ///
    /// This is equivalent to [](Self::run_cycle) and is the
    /// primary method called after each TXG commit to drain deferred
    /// cleanup work. Returns  when the queue is exhausted.
    pub fn run_cleanup_pass(&mut self) -> bool {
        self.run_cycle()
    }

    /// Run cycles until the queue is fully exhausted.
    ///
    /// Returns `true` always (queue exhausted).
    pub fn run_to_completion(&mut self) -> bool {
        loop {
            let exhausted = self.run_cycle();
            if exhausted {
                return true;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_executor::JobExecutor;
    use std::collections::HashMap;
    use tidefs_cleanup_job_core::{CleanupContext, CleanupError, CleanupPhase, JobOutcome};
    use tidefs_types_deferred_cleanup_core::{BtreeRootPointer, CleanupWorkItemV1, WorkItemKind};

    // ── Mock executor for engine tests ───────────────────────────────

    struct MockExecutor {
        /// Map: entry_id -> number of calls needed to return Completed.
        /// 0 means Completed on first call; N means Incomplete N times then Completed.
        completion_delay: HashMap<u64, u64>,
        call_count: HashMap<u64, u64>,
        /// Items that should return Fatal.
        fatal_items: Vec<u64>,
        /// Items that should return Retryable.
        retryable_items: Vec<u64>,
        completed_items: Vec<u64>,
    }

    impl MockExecutor {
        fn new() -> Self {
            Self {
                completion_delay: HashMap::new(),
                call_count: HashMap::new(),
                fatal_items: Vec::new(),
                retryable_items: Vec::new(),
                completed_items: Vec::new(),
            }
        }

        fn with_delay(mut self, entry_id: u64, delay: u64) -> Self {
            self.completion_delay.insert(entry_id, delay);
            self
        }

        fn with_fatal(mut self, entry_id: u64) -> Self {
            self.fatal_items.push(entry_id);
            self
        }

        fn with_retryable(mut self, entry_id: u64) -> Self {
            self.retryable_items.push(entry_id);
            self
        }
    }

    impl JobExecutor for MockExecutor {
        fn execute(&mut self, item: &mut CleanupWorkItemV1, _ctx: &CleanupContext) -> JobOutcome {
            let entry_id = item.inode_id; // using inode_id as proxy for entry_id in tests

            if self.fatal_items.contains(&entry_id) {
                return JobOutcome::Fatal(CleanupError::fatal(
                    "mock fatal",
                    CleanupPhase::ExtentFree,
                ));
            }

            if self.retryable_items.contains(&entry_id) {
                return JobOutcome::Retryable(CleanupError::retryable(
                    "mock retryable",
                    CleanupPhase::ExtentFree,
                ));
            }

            let count = self.call_count.entry(entry_id).or_insert(0);
            *count += 1;
            let needed = self.completion_delay.get(&entry_id).copied().unwrap_or(0);

            if *count > needed {
                item.mark_complete();
                self.completed_items.push(entry_id);
                JobOutcome::Completed
            } else {
                JobOutcome::Incomplete
            }
        }

        fn phase(&self) -> CleanupPhase {
            CleanupPhase::ExtentFree
        }

        fn name(&self) -> &str {
            "MockExecutor"
        }
    }

    fn make_item(inode: u64, kind: WorkItemKind, bytes: u64) -> CleanupWorkItemV1 {
        CleanupWorkItemV1::new(inode, kind, 1, BtreeRootPointer::EMPTY, bytes)
    }

    // ── Engine lifecycle ─────────────────────────────────────────────

    #[test]
    fn engine_new_starts_with_zero_progress() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let engine = CleanupEngine::new(queue, executor, 10);
        assert_eq!(engine.last_processed_entry_id(), 0);
        assert_eq!(engine.stats(), EngineStats::ZERO);
    }

    #[test]
    fn engine_seal_progress_roundtrip() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();

        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.run_cycle();
        assert_eq!(engine.last_processed_entry_id(), 1);

        let blob = engine.seal_progress();
        let loaded = CleanupProgress::load(&blob).unwrap();
        assert_eq!(loaded, 1);
    }

    #[test]
    fn engine_resume_skips_processed_items() {
        let mut queue1 = CleanupQueue::new();
        queue1.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        queue1.enqueue(make_item(2, WorkItemKind::UnlinkFree, 0));
        queue1.enqueue(make_item(3, WorkItemKind::UnlinkFree, 0));

        let executor1 = MockExecutor::new();
        let mut engine1 = CleanupEngine::new(queue1, executor1, 1);
        engine1.run_cycle(); // processes entry 1
        let blob = engine1.seal_progress();

        // Simulate crash + resume
        let mut queue2 = CleanupQueue::new();
        queue2.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        queue2.enqueue(make_item(2, WorkItemKind::UnlinkFree, 0));
        queue2.enqueue(make_item(3, WorkItemKind::UnlinkFree, 0));

        let executor2 = MockExecutor::new();
        let mut engine2 = CleanupEngine::resume(queue2, executor2, 10, &blob).unwrap();
        engine2.run_cycle(); // should skip entry 1, process 2 and 3

        let stats = engine2.stats();
        // entry 1 was already processed in engine1, engine2 skips it
        // entry 2 and 3 get processed
        assert!(stats.items_processed >= 2);
    }

    #[test]
    fn run_cycle_records_executed_replay_receipt() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 1024));

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_cycle();

        let receipts = engine.replay_decision_receipts();
        assert_eq!(receipts.len(), 1);
        let receipt = &receipts[0];
        assert_eq!(receipt.entry_id, 1);
        assert_eq!(receipt.entry_generation, 1);
        assert_eq!(receipt.work_kind, WorkItemKind::UnlinkFree);
        assert_eq!(receipt.decision, CleanupReplayDecision::Executed);
        assert_eq!(
            receipt.required_evidence,
            Some(CleanupReplayRequiredEvidence::ExecutorCompleted)
        );
        assert_eq!(
            receipt.validation_tier,
            CleanupReplayValidationTier::ExecutorOutcome
        );
        receipt.validate(1).unwrap();
    }

    // ── Batch size control ───────────────────────────────────────────

    #[test]
    fn run_cycle_respects_batch_size() {
        let mut queue = CleanupQueue::new();
        for i in 1..=10u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 3);
        engine.run_cycle();

        assert_eq!(engine.stats().items_processed, 3);
        assert!(!engine.stats().queue_exhausted);
    }

    #[test]
    fn run_cycle_batch_size_zero_processes_all() {
        let mut queue = CleanupQueue::new();
        for i in 1..=5u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 0);
        engine.run_cycle();

        assert_eq!(engine.stats().items_processed, 5);
        assert!(engine.stats().queue_exhausted);
    }

    // ── Multi-cycle progress ─────────────────────────────────────────

    #[test]
    fn run_cycle_progress_accumulates() {
        let mut queue = CleanupQueue::new();
        for i in 1..=6u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 2);

        engine.run_cycle();
        assert_eq!(engine.stats().items_processed, 2);
        assert!(!engine.stats().queue_exhausted);

        engine.run_cycle();
        assert_eq!(engine.stats().items_processed, 4);
        assert!(!engine.stats().queue_exhausted);

        engine.run_cycle();
        assert_eq!(engine.stats().items_processed, 6);
        assert!(engine.stats().queue_exhausted);
    }

    // ── Incomplete / retry semantics ─────────────────────────────────

    #[test]
    fn incomplete_items_retried_next_cycle() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));

        let executor = MockExecutor::new().with_delay(1, 2); // needs 3 calls to complete
        let mut engine = CleanupEngine::new(queue, executor, 10);

        // Cycle 1: incomplete
        engine.run_cycle();
        assert_eq!(engine.stats().items_incomplete, 1);
        assert_eq!(engine.stats().items_completed, 0);

        // Cycle 2: incomplete
        engine.run_cycle();
        assert_eq!(engine.stats().items_incomplete, 2);

        // Cycle 3: completed
        engine.run_cycle();
        assert_eq!(engine.stats().items_completed, 1);
    }

    #[test]
    fn retryable_items_reattempted() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));

        let executor = MockExecutor::new().with_retryable(1);
        let mut engine = CleanupEngine::new(queue, executor, 10);

        // Cycle 1: retryable
        engine.run_cycle();
        assert_eq!(engine.stats().items_retryable, 1);
        assert!(!engine.retry_ids.is_empty());
        let receipt = engine.replay_decision_receipts().last().unwrap();
        assert_eq!(receipt.decision, CleanupReplayDecision::Deferred);
        assert_eq!(
            receipt.required_evidence,
            Some(CleanupReplayRequiredEvidence::ExecutorRetryable)
        );
        receipt.validate(1).unwrap();

        // Cycle 2: retryable again (mock always returns retryable for item 1)
        engine.run_cycle();
        assert_eq!(engine.stats().items_retryable, 2);
    }

    #[test]
    fn fatal_items_are_marked_complete_and_removed() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));

        let executor = MockExecutor::new().with_fatal(1);
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_cycle();
        assert_eq!(engine.stats().items_fatal, 1);
        assert_eq!(engine.stats().items_completed, 0);
        let receipt = engine.replay_decision_receipts().last().unwrap();
        assert_eq!(receipt.decision, CleanupReplayDecision::Rejected);
        assert_eq!(
            receipt.required_evidence,
            Some(CleanupReplayRequiredEvidence::ExecutorFatal)
        );
        receipt.validate(1).unwrap();

        // The item should be marked complete in the queue
        assert_eq!(engine.queue().pending_count(), 0);
        assert!(engine.stats().queue_exhausted);
    }

    // ── Completed items skipped ──────────────────────────────────────

    #[test]
    fn already_completed_items_skipped() {
        let mut queue = CleanupQueue::new();
        let id = queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        queue.mark_complete(id);

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_cycle();
        // No new items processed (they were already complete)
        assert_eq!(engine.stats().items_processed, 0);
        let receipt = engine.replay_decision_receipts().last().unwrap();
        assert_eq!(receipt.decision, CleanupReplayDecision::Skipped);
        assert_eq!(
            receipt.required_evidence,
            Some(CleanupReplayRequiredEvidence::QueueCompletionFlag)
        );
        receipt.validate(1).unwrap();
    }

    // ── Empty queue ──────────────────────────────────────────────────

    #[test]
    fn empty_queue_exhausted_immediately() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_cycle();
        assert!(engine.stats().queue_exhausted);
        assert_eq!(engine.stats().items_processed, 0);
    }

    // ── run_to_completion ────────────────────────────────────────────

    #[test]
    fn run_to_completion_processes_all() {
        let mut queue = CleanupQueue::new();
        for i in 1..=20u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 5);

        engine.run_to_completion();
        assert!(engine.stats().queue_exhausted);
        assert_eq!(engine.stats().items_processed, 20);
        assert_eq!(engine.stats().items_completed, 20);
    }

    // ── run_with_deadline ────────────────────────────────────────────

    #[test]
    fn run_with_deadline_stops_when_deadline_hit() {
        let mut queue = CleanupQueue::new();
        for i in 1..=50u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 1);

        // Deadline already in the past → stops immediately
        let past_deadline = 0u64; // UNIX epoch 0
        let result = engine.run_with_deadline(past_deadline);
        assert!(!result); // should stop before exhaustion
    }

    #[test]
    fn run_with_deadline_continues_until_exhausted_when_plenty_of_time() {
        let mut queue = CleanupQueue::new();
        for i in 1..=5u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        // Far future deadline
        let future_deadline = u64::MAX;
        let result = engine.run_with_deadline(future_deadline);
        assert!(result);
    }

    // ── reset_stats ──────────────────────────────────────────────────

    #[test]
    fn reset_stats_zeros_counters() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_cycle();
        assert!(engine.stats().items_processed > 0);

        engine.reset_stats();
        assert_eq!(engine.stats(), EngineStats::ZERO);
    }

    // ── Mixed job types end-to-end ───────────────────────────────────

    #[test]
    fn mixed_job_types_completion() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 1024));
        queue.enqueue(make_item(2, WorkItemKind::TruncateFree, 2048));
        queue.enqueue(make_item(3, WorkItemKind::RmdirFree, 0));

        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        engine.run_to_completion();
        assert_eq!(engine.stats().items_processed, 3);
        assert_eq!(engine.stats().items_completed, 3);
        assert!(engine.stats().queue_exhausted);
    }

    // ── State machine transitions ───────────────────────────────────

    #[test]
    fn state_new_engine_is_idle() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let engine = CleanupEngine::new(queue, executor, 10);
        assert_eq!(engine.state(), CleanupEngineState::Idle);
        assert!(!engine.can_run());
        assert!(!engine.is_draining());
    }

    #[test]
    fn state_start_idle_to_running() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        assert_eq!(engine.state(), CleanupEngineState::Running);
        assert!(engine.can_run());
        assert!(!engine.is_draining());
    }

    #[test]
    fn state_start_on_running_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        let result = engine.start();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            StateTransitionError::InvalidTransition {
                from: CleanupEngineState::Running,
                to: CleanupEngineState::Running
            }
        ));
    }

    #[test]
    fn state_start_on_draining_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap(); // Running -> Draining
        let result = engine.start();
        assert!(result.is_err());
    }

    #[test]
    fn state_drain_running_to_draining() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap();
        assert_eq!(engine.state(), CleanupEngineState::Draining);
        assert!(engine.can_run());
        assert!(engine.is_draining());
    }

    #[test]
    fn state_drain_on_idle_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        let result = engine.drain(None);
        assert!(result.is_err());
    }

    #[test]
    fn state_drain_on_draining_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap();
        let result = engine.drain(None);
        assert!(result.is_err());
    }

    #[test]
    fn state_stop_draining_to_idle_when_exhausted() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap();
        engine.stats.queue_exhausted = true;
        engine.stop().unwrap();
        assert_eq!(engine.state(), CleanupEngineState::Idle);
        assert!(!engine.can_run());
    }

    #[test]
    fn state_stop_on_running_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        let result = engine.stop();
        assert!(result.is_err());
    }

    #[test]
    fn state_stop_on_idle_fails() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        let result = engine.stop();
        assert!(result.is_err());
    }

    #[test]
    fn state_force_stop_from_any_state() {
        let queue = CleanupQueue::new();
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);

        // Idle -> Idle
        engine.force_stop();
        assert_eq!(engine.state(), CleanupEngineState::Idle);

        // Running -> Idle
        engine.start().unwrap();
        engine.force_stop();
        assert_eq!(engine.state(), CleanupEngineState::Idle);

        // Draining -> Idle
        engine.start().unwrap();
        engine.drain(None).unwrap();
        engine.force_stop();
        assert_eq!(engine.state(), CleanupEngineState::Idle);
    }

    // ── State enforcement in run_cycle ───────────────────────────────

    #[test]
    fn run_cycle_auto_starts_from_idle() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        // Auto-start: Idle -> Running, processes the item
        engine.run_cycle();
        assert_eq!(engine.stats().items_processed, 1);
        assert!(engine.stats().queue_exhausted);
    }

    #[test]
    fn run_cycle_processes_when_running() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.run_cycle();
        assert!(engine.stats().items_processed > 0);
    }

    #[test]
    fn run_cycle_processes_when_draining() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap();
        engine.run_cycle();
        assert!(engine.stats().items_processed > 0);
    }

    #[test]
    fn drain_with_budget_stops_after_limit() {
        let mut queue = CleanupQueue::new();
        for i in 1..=10u64 {
            queue.enqueue(make_item(i, WorkItemKind::UnlinkFree, 0));
        }
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(Some(3)).unwrap();
        engine.run_cycle();
        // Should have processed at most 3 items, then auto-stopped
        assert!(engine.stats().items_processed <= 3);
        // Should auto-transition to Idle after budget exhausted
        assert_eq!(engine.state(), CleanupEngineState::Idle);
    }

    #[test]
    fn drain_auto_idle_when_queue_exhausted() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        engine.start().unwrap();
        engine.drain(None).unwrap();
        engine.run_cycle();
        // Queue should be exhausted; engine should auto-idle
        assert!(engine.stats().queue_exhausted);
        assert_eq!(engine.state(), CleanupEngineState::Idle);
    }

    // ── State in run_with_deadline and run_to_completion ─────────────

    #[test]
    fn run_to_completion_auto_starts_from_idle() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        queue.enqueue(make_item(2, WorkItemKind::TruncateFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        // Auto-start from Idle: processes all items to completion
        engine.run_to_completion();
        assert_eq!(engine.stats().items_processed, 2);
        assert!(engine.stats().queue_exhausted);
    }

    #[test]
    fn cleanup_pass_delegates_to_run_cycle() {
        let mut queue = CleanupQueue::new();
        queue.enqueue(make_item(1, WorkItemKind::UnlinkFree, 0));
        let executor = MockExecutor::new();
        let mut engine = CleanupEngine::new(queue, executor, 10);
        let exhausted = engine.run_cleanup_pass();
        assert!(exhausted);
        assert_eq!(engine.stats().items_processed, 1);
    }

    #[test]
    fn error_display_state_transition() {
        let err = StateTransitionError::InvalidTransition {
            from: CleanupEngineState::Idle,
            to: CleanupEngineState::Running,
        };
        let s = format!("{err}");
        assert!(s.contains("invalid transition"));
        assert!(s.contains("Idle"));
        assert!(s.contains("Running"));
    }

    #[test]
    fn error_display_not_exhausted() {
        let err = StateTransitionError::NotExhausted { pending: 5 };
        let s = format!("{err}");
        assert!(s.contains("cannot stop"));
        assert!(s.contains("5"));
    }

    #[test]
    fn state_display() {
        assert_eq!(format!("{}", CleanupEngineState::Idle), "Idle");
        assert_eq!(format!("{}", CleanupEngineState::Running), "Running");
        assert_eq!(format!("{}", CleanupEngineState::Draining), "Draining");
    }

    #[test]
    fn state_is_idle() {
        assert!(CleanupEngineState::Idle.is_idle());
        assert!(!CleanupEngineState::Running.is_idle());
        assert!(!CleanupEngineState::Draining.is_idle());
    }

    #[test]
    fn state_can_process() {
        assert!(!CleanupEngineState::Idle.can_process());
        assert!(CleanupEngineState::Running.can_process());
        assert!(CleanupEngineState::Draining.can_process());
    }
}
