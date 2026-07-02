// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BackgroundReclaim — BackgroundService for refcount-delta reclaim queue processing.
//!
//! Incrementally processes entries from the persistent reclaim queue
//! under per-tick budget control. On each `tick()`, the service
//! dequeues a batch of `ReclaimQueueEntry` entries in deterministic
//! [`ObjectKey`] order, processes deltas, and advances the cursor.
//!
//! ## Reclaim model
//!
//! The service processes a deterministic, budgeted, resumable reclaim queue
//! in sorted B-tree key order. Delta recording stays O(1) per mutation, while
//! reclamation work is bounded by each scheduler tick.

use std::sync::{Arc, Mutex};

use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_reclaim_queue_core::BPlusTreeReclaimQueue;
use tidefs_types_reclaim_queue_core::ObjectKey;

/// A single processed reclaim delta waiting for store-level deletion
/// by the owning `LocalFileSystem`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessedDelta {
    pub object_key: ObjectKey,
    pub delta: i64,
}

/// Background service that incrementally processes the refcount-delta
/// reclaim queue.
///
/// Holds a shared reference to the reclaim queue and a shared processed-
/// deltas buffer. On each tick, dequeues a batch of entries under budget,
/// removes them from the queue, records their ObjectKeys in the processed-
/// deltas buffer, and advances the cursor. The owning [`LocalFileSystem`]
/// drains processed deltas after each scheduler cycle and performs the
/// actual content-object deletion.
///
/// [`LocalFileSystem`]: crate::LocalFileSystem
pub struct BackgroundReclaim {
    queue: Arc<Mutex<BPlusTreeReclaimQueue>>,
    processed_deltas: Arc<Mutex<Vec<ProcessedDelta>>>,
    cursor: ObjectKey,
    items_processed: u64,
}

impl BackgroundReclaim {
    #[must_use]
    pub fn new(
        queue: Arc<Mutex<BPlusTreeReclaimQueue>>,
        processed_deltas: Arc<Mutex<Vec<ProcessedDelta>>>,
    ) -> Self {
        Self {
            queue,
            processed_deltas,
            cursor: ObjectKey::NONE,
            items_processed: 0,
        }
    }

    #[must_use]
    #[allow(dead_code)] // INTENT: background reclaim types for planned B+tree queue processing
    pub fn items_processed(&self) -> u64 {
        self.items_processed
    }

    #[must_use]
    #[allow(dead_code)] // INTENT: background reclaim types for planned B+tree queue processing
    pub fn queue_handle(&self) -> Arc<Mutex<BPlusTreeReclaimQueue>> {
        Arc::clone(&self.queue)
    }
}

impl BackgroundService for BackgroundReclaim {
    fn name(&self) -> &'static str {
        "reclaim"
    }

    fn priority(&self) -> ServicePriority {
        ServicePriority::Throughput
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let limit = if budget.max_items == 0 {
            256usize
        } else {
            (budget.max_items as usize).min(256)
        };

        let q = self.queue.lock().map_err(|_| ServiceError::Internal {
            service: "reclaim",
            message: "reclaim queue lock poisoned",
        })?;

        let batch = if self.cursor.is_none() {
            q.dequeue_batch(None, limit)
        } else {
            q.dequeue_batch(Some(&self.cursor), limit)
        };
        drop(q);

        let count = batch.len() as u64;
        if count == 0 {
            return Ok(TickReport {
                processed: 0,
                skipped: 0,
                errors: 0,
                items_consumed: 0,
                bytes_consumed: 0,
                has_more: false,
            });
        }

        // Delete entries from queue; record processed keys for the
        // owning LocalFileSystem to drain in tick_background_services().
        {
            let mut q = self.queue.lock().map_err(|_| ServiceError::Internal {
                service: "reclaim",
                message: "reclaim queue lock poisoned during deletion",
            })?;
            let mut processed =
                self.processed_deltas
                    .lock()
                    .map_err(|_| ServiceError::Internal {
                        service: "reclaim",
                        message: "processed deltas lock poisoned",
                    })?;
            for (key, entry) in &batch {
                q.delete(key);
                processed.push(ProcessedDelta {
                    object_key: *key,
                    delta: entry.delta,
                });
            }
        }

        if let Some((last_key, _)) = batch.last() {
            self.cursor = *last_key;
        }
        self.items_processed += count;

        let has_more = {
            let q = self.queue.lock().map_err(|_| ServiceError::Internal {
                service: "reclaim",
                message: "reclaim queue lock poisoned during has_more check",
            })?;
            !q.is_empty()
        };

        Ok(TickReport {
            processed: count,
            skipped: 0,
            errors: 0,
            items_consumed: count,
            bytes_consumed: 0,
            has_more,
        })
    }

    fn has_work(&self) -> bool {
        let q = self.queue.lock().unwrap();
        !q.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_types_reclaim_queue_core::{QueueFamily, ReclaimQueueEntry};

    fn make_entry(id: u8, delta: i64, family: QueueFamily) -> ReclaimQueueEntry {
        let mut k = [0u8; 32];
        k[0] = id;
        ReclaimQueueEntry::new(ObjectKey(k), delta, family)
    }

    fn populated_queue(count: u8) -> BPlusTreeReclaimQueue {
        let mut q = BPlusTreeReclaimQueue::new();
        for i in 1..=count {
            q.insert(make_entry(i, -1, QueueFamily::Extent));
        }
        q
    }

    fn pd() -> Arc<Mutex<Vec<ProcessedDelta>>> {
        Arc::new(Mutex::new(Vec::new()))
    }

    #[test]
    fn new_service_has_work_with_populated_queue() {
        let q = Arc::new(Mutex::new(populated_queue(10)));
        let svc = BackgroundReclaim::new(Arc::clone(&q), pd());
        assert!(svc.has_work());
        assert_eq!(svc.items_processed(), 0);
    }

    #[test]
    fn new_service_no_work_with_empty_queue() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundReclaim::new(q, pd());
        assert!(!svc.has_work());
    }

    #[test]
    fn tick_processes_batch_under_budget() {
        let q = Arc::new(Mutex::new(populated_queue(20)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let budget = ServiceBudget {
            max_items: 7,
            ..ServiceBudget::DEFAULT_TICK
        };

        let report = svc.tick(&budget).unwrap();
        assert_eq!(report.processed, 7);
        assert!(report.has_more);
        assert_eq!(svc.items_processed(), 7);

        // Queue should now have 13 entries.
        let remaining = q.lock().unwrap().len();
        assert_eq!(remaining, 13);
    }

    #[test]
    fn tick_drains_queue_completely() {
        let q = Arc::new(Mutex::new(populated_queue(5)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 5);
        assert!(!report.has_more);
        assert!(q.lock().unwrap().is_empty());
        assert!(!svc.has_work());
    }

    #[test]
    fn tick_empty_queue_returns_zero() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let mut svc = BackgroundReclaim::new(q, pd());

        let report = svc.tick(&ServiceBudget::DEFAULT_TICK).unwrap();
        assert_eq!(report.processed, 0);
        assert!(!report.has_more);
    }

    #[test]
    fn tick_unbounded_budget() {
        let q = Arc::new(Mutex::new(populated_queue(100)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let budget = ServiceBudget {
            max_items: 0, // unbounded
            ..ServiceBudget::DEFAULT_TICK
        };

        let report = svc.tick(&budget).unwrap();
        // With unbounded budget, internal batch cap is 256.
        assert_eq!(report.processed, 100);
        assert!(!report.has_more);
        assert_eq!(svc.items_processed(), 100);
        assert!(q.lock().unwrap().is_empty());
    }

    #[test]
    fn tick_multiple_ticks_to_completion() {
        let q = Arc::new(Mutex::new(populated_queue(200)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let budget = ServiceBudget {
            max_items: 50,
            ..ServiceBudget::DEFAULT_TICK
        };

        let mut total = 0u64;
        for tick_num in 1..=10 {
            let report = svc.tick(&budget).unwrap();
            total += report.processed;
            if !report.has_more {
                break;
            }
            assert!(tick_num < 10, "should complete within 10 ticks");
        }
        assert_eq!(total, 200);
        assert_eq!(svc.items_processed(), 200);
        assert!(q.lock().unwrap().is_empty());
    }

    #[test]
    fn tick_resumes_from_cursor() {
        let q = Arc::new(Mutex::new(populated_queue(30)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        // Process first 10
        let budget = ServiceBudget {
            max_items: 10,
            ..ServiceBudget::DEFAULT_TICK
        };
        svc.tick(&budget).unwrap();
        assert_eq!(svc.items_processed(), 10);

        // Process next 10 — cursor should resume from last key
        svc.tick(&budget).unwrap();
        assert_eq!(svc.items_processed(), 20);

        // Process final 10
        svc.tick(&budget).unwrap();
        assert_eq!(svc.items_processed(), 30);
        assert!(q.lock().unwrap().is_empty());
        assert!(!svc.has_work());
    }

    #[test]
    fn tick_queue_shared_between_service_and_populator() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        // Simulate file operation inserting a delta.
        {
            let mut q = q.lock().unwrap();
            q.insert(make_entry(1, -1, QueueFamily::Extent));
            q.insert(make_entry(2, -2, QueueFamily::Locator));
        }

        assert!(svc.has_work());
        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 2);

        // No more work.
        assert!(!svc.has_work());
        let report = svc.tick(&ServiceBudget::DEFAULT_TICK).unwrap();
        assert_eq!(report.processed, 0);
    }

    #[test]
    fn service_name_and_priority() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundReclaim::new(q, pd());
        assert_eq!(svc.name(), "reclaim");
        assert_eq!(svc.priority(), ServicePriority::Throughput);
    }

    #[test]
    fn items_processed_accumulates_across_ticks() {
        let q = Arc::new(Mutex::new(populated_queue(60)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let budget = ServiceBudget {
            max_items: 15,
            ..ServiceBudget::DEFAULT_TICK
        };

        svc.tick(&budget).unwrap();
        svc.tick(&budget).unwrap();
        svc.tick(&budget).unwrap();
        svc.tick(&budget).unwrap();

        assert_eq!(svc.items_processed(), 60);
    }

    #[test]
    fn queue_handle_returns_shared_reference() {
        let q = Arc::new(Mutex::new(populated_queue(5)));
        let svc = BackgroundReclaim::new(Arc::clone(&q), pd());
        let handle = svc.queue_handle();

        // Insert through the handle.
        handle
            .lock()
            .unwrap()
            .insert(make_entry(99, -1, QueueFamily::Extent));

        // Both references see the same queue.
        assert_eq!(q.lock().unwrap().len(), 6);
    }

    #[test]
    fn tick_on_queue_with_mixed_families() {
        let mut raw_q = BPlusTreeReclaimQueue::new();
        raw_q.insert(make_entry(1, -1, QueueFamily::Extent));
        raw_q.insert(make_entry(2, -2, QueueFamily::Locator));
        raw_q.insert(make_entry(3, -1, QueueFamily::Rebake));
        raw_q.insert(make_entry(4, -1, QueueFamily::InodeTombstone));
        raw_q.insert(make_entry(5, -1, QueueFamily::Extent));

        let q = Arc::new(Mutex::new(raw_q));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 5);
        assert!(q.lock().unwrap().is_empty());
        assert!(!svc.has_work());
    }

    #[test]
    fn tick_batch_at_256_cap() {
        let mut raw_q = BPlusTreeReclaimQueue::new();
        for i in 0..300u16 {
            let byte = (i % 256) as u8;
            raw_q.insert(make_entry(byte, -1, QueueFamily::Extent));
        }
        let q = Arc::new(Mutex::new(raw_q));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        // Unbounded budget: first tick processes at most 256 entries.
        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert!(report.processed <= 256);
        assert!(svc.items_processed() <= 256);
    }

    #[test]
    fn has_work_reflects_queue_state() {
        let q = Arc::new(Mutex::new(BPlusTreeReclaimQueue::new()));
        let svc = BackgroundReclaim::new(Arc::clone(&q), pd());
        assert!(!svc.has_work());

        q.lock()
            .unwrap()
            .insert(make_entry(1, -1, QueueFamily::Extent));
        assert!(svc.has_work());
    }

    #[test]
    fn tick_with_zero_budget_items_processes_default_batch() {
        let q = Arc::new(Mutex::new(populated_queue(10)));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), pd());

        let budget = ServiceBudget {
            max_items: 0,
            max_bytes: 0,
            max_ms: 0,
        };

        let report = svc.tick(&budget).unwrap();
        assert!(report.processed > 0 && report.processed <= 256);
        assert!(report.has_more || q.lock().unwrap().is_empty());
    }

    #[test]
    fn tick_records_processed_deltas() {
        let q = Arc::new(Mutex::new(populated_queue(5)));
        let processed = Arc::new(Mutex::new(Vec::new()));
        let mut svc = BackgroundReclaim::new(Arc::clone(&q), Arc::clone(&processed));

        let report = svc.tick(&ServiceBudget::UNBOUNDED).unwrap();
        assert_eq!(report.processed, 5);
        assert!(!report.has_more);

        let deltas = processed.lock().unwrap();
        assert_eq!(deltas.len(), 5);
        for (i, d) in deltas.iter().enumerate() {
            let expected_id = (i + 1) as u8;
            assert_eq!(d.object_key.0[0], expected_id);
            assert_eq!(d.delta, -1);
        }
    }
}
