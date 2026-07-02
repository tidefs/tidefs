// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! BackgroundOrphanReclamation — BackgroundService for orphan index recovery.
//!
//! Incrementally reclaims orphaned inodes from the persistent orphan index
//! under per-tick budget control. On each `tick()`, the service scans
//! the orphan index for inode IDs, stores them in a shared pending-deletions
//! buffer, and advances the cursor. The owning `LocalFileSystem` drains
//! the buffer after each scheduler cycle and performs the actual
//! content-object deletion.
//!
//! ## Orphan recovery model
//!
//! The service keeps orphan reclamation incremental, budgeted, and resumable.
//! Runtime cleanup work is queued through the persistent orphan index and
//! interleaves with other background services.

use std::sync::{Arc, Mutex};

use tidefs_background_scheduler::{
    BackgroundService, ServiceBudget, ServiceError, ServicePriority, TickReport,
};
use tidefs_orphan_index::OrphanIndex;
use tidefs_types_orphan_index_core::{OrphanCursor, OrphanRecoveryBudget};

/// Background service that incrementally reclaims orphaned inodes.
///
/// Holds a shared reference to the orphan index and a shared pending-deletions
/// buffer. On each tick, scans the index under budget and pushes recovered
/// inode IDs to the buffer. The filesystem drains the buffer and performs
/// content-object deletion after each scheduler cycle.
pub struct BackgroundOrphanReclamation {
    orphan_index: Arc<Mutex<OrphanIndex>>,
    pending_deletions: Arc<Mutex<Vec<u64>>>,
    cursor: OrphanCursor,
    items_processed: u64,
    /// Whether the last batch_recover call reported the index as exhausted
    /// (all entries through the cursor have been processed).
    cursor_exhausted: bool,
}

impl BackgroundOrphanReclamation {
    /// Create a new orphan reclamation service with the given shared
    /// orphan index and pending-deletions buffer.
    #[must_use]
    pub fn new(
        orphan_index: Arc<Mutex<OrphanIndex>>,
        pending_deletions: Arc<Mutex<Vec<u64>>>,
    ) -> Self {
        Self {
            orphan_index,
            pending_deletions,
            cursor: OrphanCursor::START,
            items_processed: 0,
            cursor_exhausted: false,
        }
    }

    /// Number of inode IDs recovered since creation.
    #[must_use]
    #[allow(dead_code)] // INTENT: background orphan reclamation types for planned inode cleanup
    pub fn items_processed(&self) -> u64 {
        self.items_processed
    }
}

impl BackgroundService for BackgroundOrphanReclamation {
    fn name(&self) -> &'static str {
        "orphan-reclamation"
    }

    fn priority(&self) -> ServicePriority {
        // Critical priority: orphan data must be reclaimed promptly to
        // avoid unbounded space leakage from unlinked-but-not-reclaimed
        // content objects. This is stricter than the default
        // from_job_kind(OrphanRecovery) which maps to LatencySensitive.
        ServicePriority::Critical
    }

    fn tick(&mut self, budget: &ServiceBudget) -> Result<TickReport, ServiceError> {
        let ob = OrphanRecoveryBudget {
            max_orphans_per_tick: budget.max_items as usize,
            ..OrphanRecoveryBudget::default()
        };

        let idx = self
            .orphan_index
            .lock()
            .map_err(|_| ServiceError::Internal {
                service: "orphan-reclamation",
                message: "orphan index lock poisoned",
            })?;
        let outcome = idx.batch_recover(self.cursor, ob);
        drop(idx);

        let count = outcome.inode_ids.len() as u64;
        if count > 0 {
            self.cursor = outcome.cursor;
            self.items_processed += count;
            let mut pending =
                self.pending_deletions
                    .lock()
                    .map_err(|_| ServiceError::Internal {
                        service: "orphan-reclamation",
                        message: "pending deletions lock poisoned",
                    })?;
            pending.extend(outcome.inode_ids.iter().copied());
        }

        self.cursor_exhausted = outcome.exhausted;

        Ok(TickReport {
            processed: count,
            skipped: 0,
            errors: 0,
            items_consumed: count,
            bytes_consumed: 0,
            has_more: !outcome.exhausted && count > 0,
        })
    }

    fn has_work(&self) -> bool {
        let idx = self.orphan_index.lock().unwrap();
        !idx.is_empty() && !self.cursor_exhausted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_orphan_index::{OrphanEntry, OrphanEntryFlags};

    fn orphan_entry(inode_id: u64) -> OrphanEntry {
        OrphanEntry::new(inode_id, inode_id, 0, OrphanEntryFlags::NONE)
    }

    #[test]
    fn service_starts_with_has_work_false_on_empty_index() {
        let idx = Arc::new(Mutex::new(OrphanIndex::new()));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let svc = BackgroundOrphanReclamation::new(idx, pending);
        assert!(!svc.has_work());
    }

    #[test]
    fn has_work_true_when_orphans_present() {
        let mut idx = OrphanIndex::new();
        idx.insert(42, orphan_entry(42));
        let idx = Arc::new(Mutex::new(idx));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let svc = BackgroundOrphanReclamation::new(idx, pending);
        assert!(svc.has_work());
    }

    #[test]
    fn tick_populates_pending_deletions() {
        let mut idx = OrphanIndex::new();
        for i in 1..=5u64 {
            idx.insert(i, orphan_entry(i));
        }
        let idx = Arc::new(Mutex::new(idx));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let mut svc = BackgroundOrphanReclamation::new(idx, pending.clone());

        let budget = ServiceBudget::DEFAULT_TICK;
        let report = svc.tick(&budget).expect("tick should succeed");
        assert!(report.processed > 0);
        assert_eq!(report.processed, 5);

        let pending = pending.lock().unwrap();
        assert_eq!(pending.len(), 5);
        assert_eq!(pending.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn tick_on_empty_index_returns_no_progress() {
        let idx = Arc::new(Mutex::new(OrphanIndex::new()));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let mut svc = BackgroundOrphanReclamation::new(idx, pending);

        let budget = ServiceBudget::DEFAULT_TICK;
        let report = svc.tick(&budget).expect("tick should succeed");
        assert_eq!(report.processed, 0);
        assert!(!report.has_more);
    }

    #[test]
    fn cursor_advances_across_ticks() {
        let mut idx = OrphanIndex::new();
        for i in 1..31u64 {
            idx.insert(i, orphan_entry(i));
        }
        let idx = Arc::new(Mutex::new(idx));
        let pending = Arc::new(Mutex::new(Vec::new()));
        let mut svc = BackgroundOrphanReclamation::new(idx, pending);

        let small_budget = ServiceBudget {
            max_items: 10,
            max_bytes: 10_000_000,
            max_ms: 500,
        };
        let r1 = svc.tick(&small_budget).expect("tick 1");
        assert_eq!(r1.processed, 10);
        assert!(r1.has_more);

        let r2 = svc.tick(&small_budget).expect("tick 2");
        assert_eq!(r2.processed, 10);
        assert!(r2.has_more);

        let r3 = svc.tick(&small_budget).expect("tick 3");
        assert_eq!(r3.processed, 10);
        assert!(!r3.has_more);

        assert!(!svc.has_work());
    }
}
