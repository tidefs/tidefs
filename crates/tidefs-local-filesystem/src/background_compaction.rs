// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BackgroundCompaction — BackgroundService for B+tree compaction.
//!
//! Periodically compacts B+tree-backed data structures that experience
//! insert/delete churn. Compaction rebuilds trees from sorted entries,
//! restoring canonical fanout and eliminating sparse nodes.
//!
//! ## Design (better than ZFS/Ceph)
//!
//! - **ZFS**: ZAP micro-zap converts to fat-zap at 2K entries, but
//!   neither form compacts after deletes. Long-running datasets
//!   accumulate sparse ZAP objects that waste space and slow lookups.
//!   No background compaction exists.
//! - **Ceph**: OSDMap grows unboundedly with cluster history; no
//!   compaction of historical epochs. OMAP (leveldb) does compact
//!   but is opaque to the filesystem layer.
//! - **TideFS**: BackgroundCompaction periodically compacts B+tree-
//!   backed structures under per-tick budget control with configurable
//!   fill thresholds. Trees that fall below threshold are rebuilt to
//!   canonical fanout, reclaiming space and improving locality.

use std::sync::{Arc, Mutex};

use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;

/// Default fill threshold for triggering compaction.
/// Trees with leaf fill below 25% are candidates.
pub const DEFAULT_COMPACTION_THRESHOLD: f64 = 0.25;

/// Background service that periodically compacts the reclaim queue's
/// underlying B+tree.
///
/// Holds a shared reference to the reclaim queue. On each tick, checks
/// the tree's fill ratio. If it falls below the configured threshold,
/// rebuilds the tree from sorted entries to restore canonical fanout.
///
/// Scheduled at BestEffort priority — compaction is a housekeeping
/// operation that improves space efficiency and lookup locality but
/// is not latency-critical.
///
/// # Architecture note
///
/// The current B+tree's `delete()` performs an inline rebuild-from-entries
/// (O(n)), so trees normally stay compact. This BackgroundService exists
/// as infrastructure for the planned O(log n) delete optimization (#1197
/// bottom-up merge pass), after which sparse trees will accumulate and
/// need periodic background compaction. The service also handles trees
/// that become sparse through clear-and-rebuild or batch-load patterns.
pub struct BackgroundCompaction {
    queue: Arc<Mutex<BPlusTreeReclaimQueue>>,
    threshold: f64,
    compactions_run: u64,
    last_fill_percent: f64,
}

impl BackgroundCompaction {
    /// Create a new compaction service wrapping `queue`.
    ///
    /// Uses [`DEFAULT_COMPACTION_THRESHOLD`] (0.25) — trees with
    /// leaf fill below 25% will be compacted.
    #[must_use]
    pub fn new(queue: Arc<Mutex<BPlusTreeReclaimQueue>>) -> Self {
        Self {
            queue,
            threshold: DEFAULT_COMPACTION_THRESHOLD,
            compactions_run: 0,
            last_fill_percent: 1.0,
        }
    }

    /// Create a compaction service with a custom fill threshold.
    #[must_use]
    #[allow(dead_code)] // INTENT: background compaction types for planned segment reclamation
    pub fn with_threshold(queue: Arc<Mutex<BPlusTreeReclaimQueue>>, threshold: f64) -> Self {
        Self {
            queue,
            threshold: threshold.clamp(0.0, 1.0),
            compactions_run: 0,
            last_fill_percent: 1.0,
        }
    }

    /// Number of compactions performed since creation.
    #[must_use]
    #[allow(dead_code)] // INTENT: background compaction types for planned segment reclamation
    pub fn compactions_run(&self) -> u64 {
        self.compactions_run
    }

    /// Fill percentage observed on the last tick.
    #[must_use]
    #[allow(dead_code)] // INTENT: background compaction types for planned segment reclamation
    pub fn last_fill_percent(&self) -> f64 {
        self.last_fill_percent
    }

    /// Queue handle for sharing with other components.
    #[must_use]
    #[allow(dead_code)] // INTENT: background compaction types for planned segment reclamation
    pub fn queue_handle(&self) -> Arc<Mutex<BPlusTreeReclaimQueue>> {
        Arc::clone(&self.queue)
    }
}

impl BackgroundService for BackgroundCompaction {
    fn name(&self) -> &'static str {
        "compaction"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::BestEffort
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        // Guard against empty budget — compaction is at least O(n).
        if budget.max_items == 0 && budget.max_bytes == 0 {
            return Ok(TickReport {
                processed: 0,
                skipped: 0,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more: false,
            });
        }

        let mut q = self.queue.lock().map_err(|_| ServiceError::Internal {
            service: "compaction",
            message: "reclaim queue lock poisoned",
        })?;

        let count = q.len();
        self.last_fill_percent = q.fill_percent();

        if count == 0 || self.last_fill_percent >= self.threshold {
            return Ok(TickReport {
                processed: 0,
                skipped: 0,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more: false,
            });
        }

        // Gate: skip compaction if tree is too large for a single tick.
        if count > budget.max_items as usize && budget.max_items > 0 {
            return Ok(TickReport {
                processed: 0,
                skipped: 1,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more: true,
            });
        }

        let before_nodes = q.node_count();
        let compacted = q.compact_if_needed(self.threshold);
        let after_nodes = q.node_count();

        if compacted {
            self.compactions_run = self.compactions_run.saturating_add(1);
        }

        Ok(TickReport {
            processed: if compacted { 1 } else { 0 },
            skipped: 0,
            errors: 0,
            items_consumed: before_nodes.saturating_sub(after_nodes) as u64,
            bytes_consumed: 0,
            has_more: false,
        })
    }

    fn has_work(&self) -> bool {
        match self.queue.lock() {
            Ok(q) => !q.is_empty() && q.fill_percent() < self.threshold,
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_reclaim_queue_core::{ObjectKey, QueueFamily, ReclaimQueueEntry};

    /// Helper: build an ObjectKey from a u8 id byte.
    fn key(id: u8) -> ObjectKey {
        let mut k = [0u8; 32];
        k[0] = id;
        ObjectKey(k)
    }

    /// Helper: build a ReclaimQueueEntry.
    fn entry(id: u8, delta: i64, family: QueueFamily) -> ReclaimQueueEntry {
        ReclaimQueueEntry::new(key(id), delta, family)
    }

    #[test]
    fn compaction_idle_on_empty_queue() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let mut svc = BackgroundCompaction::new(Arc::clone(&q));
        let budget = ServiceBudget::default();
        assert!(!svc.has_work());
        let report = svc.tick(&budget).unwrap();
        assert_eq!(report.processed, 0);
    }

    #[test]
    fn compaction_idle_on_dense_tree() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        for i in 0..200u8 {
            q.lock().unwrap().insert(entry(i, -1, QueueFamily::Extent));
        }
        let mut svc = BackgroundCompaction::new(Arc::clone(&q));
        let budget = ServiceBudget {
            max_items: 500,
            max_bytes: 1_000_000,
            max_ms: 1000,
        };
        let report = svc.tick(&budget).unwrap();
        // Dense tree — no compaction needed.
        assert_eq!(report.processed, 0);
        assert!(svc.last_fill_percent() >= DEFAULT_COMPACTION_THRESHOLD);
    }

    #[test]
    fn compaction_service_registers_without_panic() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundCompaction::new(Arc::clone(&q));
        assert_eq!(svc.name(), "compaction");
        assert_eq!(svc.priority(), ServicePriority::BestEffort);
        assert_eq!(svc.compactions_run(), 0);
    }

    #[test]
    fn compaction_tick_respects_zero_budget() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        for i in 0..100u8 {
            q.lock().unwrap().insert(entry(i, -1, QueueFamily::Extent));
        }
        let mut svc = BackgroundCompaction::new(Arc::clone(&q));
        let budget = ServiceBudget::default(); // max_items=0, max_bytes=0
        let report = svc.tick(&budget).unwrap();
        assert_eq!(report.processed, 0);
    }

    #[test]
    fn compaction_custom_threshold() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundCompaction::with_threshold(Arc::clone(&q), 0.75);
        assert_eq!(svc.threshold, 0.75);
    }

    #[test]
    fn compaction_queue_handle_shares_reference() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundCompaction::new(Arc::clone(&q));
        let handle = svc.queue_handle();
        handle
            .lock()
            .unwrap()
            .insert(entry(1, -1, QueueFamily::Extent));
        assert_eq!(q.lock().unwrap().len(), 1);
    }

    #[test]
    fn compaction_threshold_clamped() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc1 = BackgroundCompaction::with_threshold(Arc::clone(&q), -0.5);
        assert_eq!(svc1.threshold, 0.0);
        let svc2 = BackgroundCompaction::with_threshold(Arc::clone(&q), 1.5);
        assert_eq!(svc2.threshold, 1.0);
    }
}
