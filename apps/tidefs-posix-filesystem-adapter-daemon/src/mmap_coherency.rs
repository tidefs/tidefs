// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
#![allow(dead_code, unused_imports)]
//! Mmap cluster coherency: page invalidation on remote writes.
//!
//! When a file is mmap'd on multiple cluster nodes and one node writes,
//! the other nodes' mmap pages must be invalidated to maintain coherency.
//! `MmapCoherency` implements [`InvalidationSink`] from the cluster
//! invalidation feed, tracks registered mmap inodes, and sends
//! `FUSE_NOTIFY_INVAL_INODE` to evict stale kernel page-cache pages.
//!
//! # Registration
//!
//! Calling `register(inode, generation)` registers an inode as
//! mmap'd. When a remote-write invalidation for this inode arrives
//! with a higher generation, the kernel page cache is invalidated.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tidefs_invalidation_feed::{
    DatasetId, FollowerInvalidationProcessor, InodeId, InvalidationBatch, InvalidationSink,
};

/// Statistics for the mmap coherency subsystem.
#[derive(Debug, Default)]
pub struct MmapCoherencyStats {
    pub mmap_registrations: AtomicU64,
    pub mmap_deregistrations: AtomicU64,
    pub invalidations_received: AtomicU64,
    pub dirty_invalidations_preserved: AtomicU64,
    pub notification_failures: AtomicU64,
    pub pages_invalidated: AtomicU64,
    pub coherency_conflicts: AtomicU64,
}

impl MmapCoherencyStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> MmapCoherencyStatsSnapshot {
        MmapCoherencyStatsSnapshot {
            mmap_registrations: self.mmap_registrations.load(Ordering::Relaxed),
            mmap_deregistrations: self.mmap_deregistrations.load(Ordering::Relaxed),
            invalidations_received: self.invalidations_received.load(Ordering::Relaxed),
            dirty_invalidations_preserved: self
                .dirty_invalidations_preserved
                .load(Ordering::Relaxed),
            notification_failures: self.notification_failures.load(Ordering::Relaxed),
            pages_invalidated: self.pages_invalidated.load(Ordering::Relaxed),
            coherency_conflicts: self.coherency_conflicts.load(Ordering::Relaxed),
        }
    }
}

/// Non-atomic snapshot of MmapCoherencyStats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MmapCoherencyStatsSnapshot {
    pub mmap_registrations: u64,
    pub mmap_deregistrations: u64,
    pub invalidations_received: u64,
    pub dirty_invalidations_preserved: u64,
    pub notification_failures: u64,
    pub pages_invalidated: u64,
    pub coherency_conflicts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmapRegistration {
    generation: u64,
    active: bool,
}

/// A dirty/writeback-state check callback.
///
/// The callback receives an inode number and returns `true` when the inode
/// has dirty or writeback-pending bytes.  When set, the invalidation sink
/// consults this callback before sending `FUSE_NOTIFY_INVAL_INODE` so that
/// dirty/writeback pages are preserved and the invalidation is retried later
/// (authority contract:
/// "Dirty and writeback pages must not be silently invalidated").
pub type DirtyStateCheck = Box<dyn Fn(u64) -> bool + Send + Sync>;

type InodeInvalidator = Box<dyn Fn(u64) -> io::Result<()> + Send + Sync>;

/// Mmap cluster coherency manager.
///
/// # Dirty/writeback preservation
///
/// When a [`DirtyStateCheck`] callback is set (via
/// [`MmapCoherency::set_dirty_check`]),
/// the invalidation sink consults it before sending
/// `FUSE_NOTIFY_INVAL_INODE`.  Inodes with dirty or writeback-pending
/// bytes are preserved; their page-cache entries are not invalidated until a
/// later coherency tick observes them clean, per the authority contract in
/// `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`.
pub struct MmapCoherency {
    registrations: Mutex<BTreeMap<u64, MmapRegistration>>,
    processor: Mutex<FollowerInvalidationProcessor>,
    /// Latest per-inode invalidation generation retained while dirty or
    /// writeback-pending bytes prevent immediate kernel-cache invalidation,
    /// while a known registration is inactive, or while the kernel
    /// notification cannot be confirmed.
    deferred_invalidations: Mutex<VecDeque<(u64, u64)>>,
    /// Alternates the single available slot when a one-event tick has both a
    /// feed event and a deferred retry waiting.
    retry_deferred_next: AtomicBool,
    invalidate_inode: InodeInvalidator,
    /// Optional callback to check whether an inode has dirty or
    /// writeback-pending bytes.  When set and the callback returns
    /// `true`, mmap invalidation for that inode is deferred until the dirty
    /// state is resolved.
    dirty_check: Mutex<Option<DirtyStateCheck>>,
    pub stats: MmapCoherencyStats,
}

impl MmapCoherency {
    pub fn new(notifier: Arc<Mutex<Option<fuser::Notifier>>>) -> Self {
        Self::with_invalidator(Box::new(move |ino| {
            let guard = notifier
                .lock()
                .map_err(|_| io::Error::other("FUSE notifier lock poisoned"))?;
            let notifier = guard.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::WouldBlock, "FUSE notifier is not installed")
            })?;
            notifier.inval_inode(ino, 0, -1)
        }))
    }

    fn with_invalidator(invalidate_inode: InodeInvalidator) -> Self {
        Self {
            registrations: Mutex::new(BTreeMap::new()),
            processor: Mutex::new(FollowerInvalidationProcessor::new()),
            deferred_invalidations: Mutex::new(VecDeque::new()),
            retry_deferred_next: AtomicBool::new(false),
            invalidate_inode,
            dirty_check: Mutex::new(None),
            stats: MmapCoherencyStats::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn new_for_test(
        invalidate_inode: impl Fn(u64) -> io::Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self::with_invalidator(Box::new(invalidate_inode))
    }

    /// Install a dirty-state check callback.
    ///
    /// When set, the invalidation sink calls this callback before sending
    /// `FUSE_NOTIFY_INVAL_INODE`.  If the callback returns `true` (inode
    /// has dirty or writeback-pending bytes), the invalidation is retained for
    /// a later coherency tick.
    pub fn set_dirty_check(&self, check: Option<DirtyStateCheck>) {
        *self.dirty_check.lock().unwrap() = check;
    }

    pub fn register(&self, ino: u64, generation: u64) {
        let mut regs = self.registrations.lock().unwrap();
        let entry = regs.entry(ino).or_insert(MmapRegistration {
            generation: 0,
            active: false,
        });
        // Close/reopen must not move the invalidation fence backward.  A
        // deferred event may still be waiting for this registration to become
        // active again, and a lower reopen hint must not make older cache state
        // current in the meantime.
        entry.generation = entry.generation.max(generation);
        entry.active = true;
        drop(regs);
        self.stats
            .mmap_registrations
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn deregister(&self, ino: u64) {
        let mut regs = self.registrations.lock().unwrap();
        if let Some(entry) = regs.get_mut(&ino) {
            entry.active = false;
        }
        drop(regs);
        self.stats
            .mmap_deregistrations
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn is_registered(&self, ino: u64) -> bool {
        self.registrations
            .lock()
            .unwrap()
            .get(&ino)
            .is_some_and(|r| r.active)
    }

    pub fn registration_count(&self) -> usize {
        self.registrations
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.active)
            .count()
    }

    pub fn enqueue_batch(&self, batch: InvalidationBatch) {
        self.processor.lock().unwrap().enqueue_batch(batch);
    }

    fn retryable_deferred_invalidation_count(&self) -> usize {
        let registrations = self.registrations.lock().unwrap();
        self.deferred_invalidations
            .lock()
            .unwrap()
            .iter()
            .filter(|(ino, _)| registrations.get(ino).is_some_and(|entry| entry.active))
            .count()
    }

    pub fn process_tick(&self, event_budget: usize) -> usize {
        if event_budget == 0 {
            return 0;
        }

        let mut processor = self.processor.lock().unwrap();
        // A retained invalidation for a closed inode cannot make progress
        // until register() reactivates that inode. Keep it pending, but do
        // not let it consume retry budget or displace new feed events.
        let deferred_pending = self.retryable_deferred_invalidation_count();
        let feed_pending = processor.pending_event_count();
        let (deferred_budget, feed_budget) = match (deferred_pending, feed_pending) {
            (0, _) => (0, event_budget),
            (_, 0) => (event_budget, 0),
            _ if event_budget == 1 => {
                if self.retry_deferred_next.fetch_xor(true, Ordering::Relaxed) {
                    (1, 0)
                } else {
                    (0, 1)
                }
            }
            _ => {
                let mut deferred_budget = (event_budget / 2).min(deferred_pending);
                let feed_budget = (event_budget - deferred_budget).min(feed_pending);
                deferred_budget += (event_budget - deferred_budget - feed_budget)
                    .min(deferred_pending - deferred_budget);
                (deferred_budget, feed_budget)
            }
        };
        let mut sink = MmapInvalidationSink {
            registrations: &self.registrations,
            invalidate_inode: &self.invalidate_inode,
            dirty_check: &self.dirty_check,
            deferred_invalidations: &self.deferred_invalidations,
            stats: &self.stats,
        };
        let retried = sink.retry_deferred(deferred_budget);
        retried + processor.process_tick(&mut sink, feed_budget)
    }

    pub fn pending_event_count(&self) -> usize {
        let feed_pending = self.processor.lock().unwrap().pending_event_count();
        feed_pending + self.deferred_invalidation_count()
    }

    /// Number of newer inode invalidations waiting for dirty/writeback state
    /// to become clean, a known registration to become active, or a kernel
    /// notification retry.
    #[must_use]
    pub fn deferred_invalidation_count(&self) -> usize {
        self.deferred_invalidations.lock().unwrap().len()
    }
}

struct MmapInvalidationSink<'a> {
    registrations: &'a Mutex<BTreeMap<u64, MmapRegistration>>,
    invalidate_inode: &'a InodeInvalidator,
    /// Reference to the optional dirty-state check callback owned by
    /// [`MmapCoherency`].  When the callback is set and returns `true`,
    /// invalidation for dirty/writeback inodes is deferred.
    dirty_check: &'a Mutex<Option<DirtyStateCheck>>,
    /// Latest deferred generation for each inode whose dirty/writeback state
    /// currently prevents invalidation.
    deferred_invalidations: &'a Mutex<VecDeque<(u64, u64)>>,
    stats: &'a MmapCoherencyStats,
}

impl MmapInvalidationSink<'_> {
    fn defer_invalidation(&self, ino: u64, generation: u64) {
        let mut deferred = self.deferred_invalidations.lock().unwrap();
        if let Some((_, queued_generation)) = deferred
            .iter_mut()
            .find(|(queued_ino, _)| *queued_ino == ino)
        {
            *queued_generation = (*queued_generation).max(generation);
        } else {
            deferred.push_back((ino, generation));
        }
    }

    fn retry_deferred(&mut self, event_budget: usize) -> usize {
        let scan_budget = self.deferred_invalidations.lock().unwrap().len();
        let mut attempted = 0;
        let mut scanned = 0;
        while attempted < event_budget && scanned < scan_budget {
            let Some((ino, generation)) = self.deferred_invalidations.lock().unwrap().pop_front()
            else {
                break;
            };
            scanned += 1;
            let is_active = self
                .registrations
                .lock()
                .unwrap()
                .get(&ino)
                .is_some_and(|entry| entry.active);
            if !is_active {
                self.defer_invalidation(ino, generation);
                continue;
            }
            self.invalidate_inode_inner(ino, generation, false);
            attempted += 1;
        }
        attempted
    }

    fn invalidate_inode_inner(&mut self, ino_u64: u64, generation: u64, newly_received: bool) {
        if newly_received {
            self.stats
                .invalidations_received
                .fetch_add(1, Ordering::Relaxed);
        }

        let (is_actionable, retain_until_active) = {
            let regs = self.registrations.lock().unwrap();
            match regs.get(&ino_u64) {
                Some(entry) if generation > entry.generation && entry.active => (true, false),
                Some(entry) if generation > entry.generation && !entry.active => (false, true),
                _ => (false, false),
            }
        };
        if retain_until_active {
            self.defer_invalidation(ino_u64, generation);
            return;
        }
        if !is_actionable {
            return;
        }

        let is_dirty = self
            .dirty_check
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|check| check(ino_u64));
        if is_dirty {
            let is_still_actionable = {
                let regs = self.registrations.lock().unwrap();
                regs.get(&ino_u64)
                    .is_some_and(|entry| generation > entry.generation)
            };
            if is_still_actionable {
                self.defer_invalidation(ino_u64, generation);
                if newly_received {
                    self.stats
                        .dirty_invalidations_preserved
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            return;
        }

        if (self.invalidate_inode)(ino_u64).is_err() {
            self.stats
                .notification_failures
                .fetch_add(1, Ordering::Relaxed);
            let is_still_actionable = {
                let regs = self.registrations.lock().unwrap();
                regs.get(&ino_u64)
                    .is_some_and(|entry| generation > entry.generation)
            };
            if is_still_actionable {
                self.defer_invalidation(ino_u64, generation);
            }
            return;
        }

        let should_invalidate = {
            let mut regs = self.registrations.lock().unwrap();
            match regs.get_mut(&ino_u64) {
                Some(ref mut entry) if generation > entry.generation => {
                    entry.generation = generation;
                    true
                }
                _ => false,
            }
        };
        if should_invalidate {
            self.stats
                .coherency_conflicts
                .fetch_add(1, Ordering::Relaxed);
            self.stats.pages_invalidated.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl InvalidationSink for MmapInvalidationSink<'_> {
    fn invalidate_inode(&mut self, ino: InodeId, generation: u64) {
        self.invalidate_inode_inner(ino.0, generation, true);
    }

    fn invalidate_entry(&mut self, _parent: InodeId, _name: &[u8]) {}
    fn invalidate_directory(&mut self, _ino: InodeId) {}
    fn invalidate_dataset(&mut self, _dataset: DatasetId) {}
    fn invalidate_range(&mut self, _ino: InodeId, _offset: u64, _length: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_invalidation_feed::{CommitGroupId, DatasetId, InvalidationEvent};

    fn batch(ino: u64, gen: u64) -> InvalidationBatch {
        InvalidationBatch::new(
            DatasetId::new(1),
            CommitGroupId::new(1),
            vec![InvalidationEvent::Inode {
                ino: InodeId::new(ino),
                generation: gen,
            }],
        )
    }

    fn new_coherency() -> MmapCoherency {
        MmapCoherency::new_for_test(|_| Ok(()))
    }

    #[test]
    fn register_makes_inode_active() {
        let c = new_coherency();
        c.register(42, 1);
        assert!(c.is_registered(42));
        assert_eq!(c.registration_count(), 1);
    }

    #[test]
    fn deregister_deactivates() {
        let c = new_coherency();
        c.register(42, 1);
        c.deregister(42);
        assert!(!c.is_registered(42));
    }

    #[test]
    fn higher_gen_invalidation_triggers() {
        let c = new_coherency();
        c.register(42, 1);
        c.enqueue_batch(batch(42, 2));
        let n = c.process_tick(10);
        assert_eq!(n, 1);
        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn reregister_active_inode_preserves_newer_generation() {
        let c = new_coherency();
        c.register(42, 1);
        c.enqueue_batch(batch(42, 4));
        assert_eq!(c.process_tick(10), 1);

        // A second open registers the same active inode with generation zero.
        // It must not make an older invalidation actionable again.
        c.register(42, 0);
        c.enqueue_batch(batch(42, 3));
        assert_eq!(c.process_tick(10), 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 2);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn dirty_check_coalesces_and_retries_after_inode_is_clean() {
        let c = new_coherency();
        let dirty = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let dirty_check = Arc::clone(&dirty);
        c.register(42, 1);
        c.set_dirty_check(Some(Box::new(move |ino| {
            ino == 42 && dirty_check.load(Ordering::Relaxed)
        })));

        c.enqueue_batch(batch(42, 2));
        c.enqueue_batch(batch(42, 4));
        assert_eq!(c.process_tick(10), 2);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 2);
        assert_eq!(s.dirty_invalidations_preserved, 2);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(c.pending_event_count(), 1);

        dirty.store(false, Ordering::Relaxed);
        assert_eq!(c.process_tick(10), 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 2);
        assert_eq!(s.dirty_invalidations_preserved, 2);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
        assert_eq!(c.deferred_invalidation_count(), 0);
        assert_eq!(c.pending_event_count(), 0);

        let regs = c.registrations.lock().unwrap();
        let registration = regs.get(&42).expect("registered inode remains tracked");
        assert!(registration.active);
        assert_eq!(registration.generation, 4);
    }

    #[test]
    fn dirty_deferred_invalidation_is_retried_once_per_tick() {
        let c = new_coherency();
        let calls = Arc::new(AtomicU64::new(0));
        let check_calls = Arc::clone(&calls);
        c.register(42, 1);
        c.set_dirty_check(Some(Box::new(move |ino| {
            check_calls.fetch_add(1, Ordering::Relaxed);
            ino == 42
        })));

        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(16), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);

        assert_eq!(c.process_tick(16), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(c.deferred_invalidation_count(), 1);
    }

    #[test]
    fn deferred_invalidation_survives_deregister_and_reopen() {
        let calls = Arc::new(AtomicU64::new(0));
        let notify_calls = Arc::clone(&calls);
        let dirty = Arc::new(AtomicBool::new(true));
        let dirty_check = Arc::clone(&dirty);
        let c = MmapCoherency::new_for_test(move |_| {
            notify_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        c.register(42, 1);
        c.set_dirty_check(Some(Box::new(move |ino| {
            ino == 42 && dirty_check.load(Ordering::Relaxed)
        })));

        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(10), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        c.deregister(42);
        dirty.store(false, Ordering::Relaxed);
        assert_eq!(c.process_tick(10), 0);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 0);

        c.register(42, 0);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 1);
        assert_eq!(c.process_tick(10), 1);
        assert_eq!(c.deferred_invalidation_count(), 0);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 2);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 1);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn inactive_deferred_invalidation_does_not_consume_feed_budget() {
        let c = new_coherency();
        c.register(42, 1);
        c.deregister(42);
        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(1), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);

        for ino in 100..102 {
            c.register(ino, 0);
            c.enqueue_batch(batch(ino, 1));
        }

        assert_eq!(c.process_tick(2), 2);
        assert_eq!(c.stats.snapshot().pages_invalidated, 2);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(c.pending_event_count(), 1);
    }

    #[test]
    fn notification_failure_retains_generation_for_retry() {
        let calls = Arc::new(AtomicU64::new(0));
        let fail = Arc::new(AtomicBool::new(true));
        let check_calls = Arc::clone(&calls);
        let should_fail = Arc::clone(&fail);
        let c = MmapCoherency::new_for_test(move |_| {
            check_calls.fetch_add(1, Ordering::Relaxed);
            if should_fail.load(Ordering::Relaxed) {
                Err(io::Error::other("injected notification failure"))
            } else {
                Ok(())
            }
        });
        c.register(42, 1);
        c.enqueue_batch(batch(42, 2));

        assert_eq!(c.process_tick(10), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);
        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.notification_failures, 1);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 1);

        fail.store(false, Ordering::Relaxed);
        assert_eq!(c.process_tick(10), 1);
        assert_eq!(calls.load(Ordering::Relaxed), 2);
        assert_eq!(c.deferred_invalidation_count(), 0);
        let s = c.stats.snapshot();
        assert_eq!(s.notification_failures, 1);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 2);
    }

    #[test]
    fn small_deferred_queue_does_not_waste_feed_budget() {
        let c = new_coherency();
        c.register(42, 1);
        c.set_dirty_check(Some(Box::new(|ino| ino == 42)));

        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(1), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);

        for ino in 100..103 {
            c.register(ino, 0);
            c.enqueue_batch(batch(ino, 1));
        }

        assert_eq!(c.process_tick(4), 4);
        assert_eq!(c.pending_event_count(), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(c.stats.snapshot().pages_invalidated, 3);
    }

    #[test]
    fn dirty_check_ignores_lower_generation_invalidation() {
        let c = new_coherency();
        let calls = Arc::new(AtomicU64::new(0));
        let check_calls = Arc::clone(&calls);
        c.register(42, 5);
        c.set_dirty_check(Some(Box::new(move |ino| {
            check_calls.fetch_add(1, Ordering::Relaxed);
            ino == 42
        })));

        c.enqueue_batch(batch(42, 3));
        assert_eq!(c.process_tick(10), 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 0);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn dirty_check_ignores_unregistered_inode_invalidation() {
        let c = new_coherency();
        let calls = Arc::new(AtomicU64::new(0));
        let check_calls = Arc::clone(&calls);
        c.set_dirty_check(Some(Box::new(move |ino| {
            check_calls.fetch_add(1, Ordering::Relaxed);
            ino == 99
        })));

        c.enqueue_batch(batch(99, 1));
        assert_eq!(c.process_tick(10), 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 0);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn newer_invalidation_received_while_inactive_survives_reopen() {
        let notify_calls = Arc::new(AtomicU64::new(0));
        let notify_count = Arc::clone(&notify_calls);
        let dirty_check_calls = Arc::new(AtomicU64::new(0));
        let dirty_check_count = Arc::clone(&dirty_check_calls);
        let c = MmapCoherency::new_for_test(move |_| {
            notify_count.fetch_add(1, Ordering::Relaxed);
            Ok(())
        });
        c.register(42, 1);
        c.deregister(42);
        c.set_dirty_check(Some(Box::new(move |ino| {
            dirty_check_count.fetch_add(1, Ordering::Relaxed);
            assert_eq!(ino, 42);
            false
        })));

        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(10), 1);
        assert_eq!(c.deferred_invalidation_count(), 1);
        assert_eq!(notify_calls.load(Ordering::Relaxed), 0);
        assert_eq!(dirty_check_calls.load(Ordering::Relaxed), 0);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 0);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);

        c.register(42, 0);
        assert_eq!(c.process_tick(10), 1);
        assert_eq!(c.deferred_invalidation_count(), 0);
        assert_eq!(notify_calls.load(Ordering::Relaxed), 1);
        assert_eq!(dirty_check_calls.load(Ordering::Relaxed), 1);
        assert_eq!(c.registrations.lock().unwrap()[&42].generation, 2);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 0);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn lower_gen_invalidation_ignored() {
        let c = new_coherency();
        c.register(42, 5);
        c.enqueue_batch(batch(42, 3));
        c.process_tick(10);
        let s = c.stats.snapshot();
        assert_eq!(s.coherency_conflicts, 0);
    }

    #[test]
    fn unregistered_inode_ignored() {
        let c = new_coherency();
        c.enqueue_batch(batch(99, 1));
        c.process_tick(10);
        let s = c.stats.snapshot();
        assert_eq!(s.coherency_conflicts, 0);
    }

    #[test]
    fn stats_track_counts() {
        let c = new_coherency();
        c.register(10, 1);
        c.register(20, 1);
        c.deregister(20);
        let s = c.stats.snapshot();
        assert_eq!(s.mmap_registrations, 2);
        assert_eq!(s.mmap_deregistrations, 1);
    }

    #[test]
    fn budget_respected() {
        let c = new_coherency();
        c.register(1, 0);
        c.register(2, 0);
        c.register(3, 0);
        c.enqueue_batch(InvalidationBatch::new(
            DatasetId::new(1),
            CommitGroupId::new(1),
            vec![
                InvalidationEvent::Inode {
                    ino: InodeId::new(1),
                    generation: 1,
                },
                InvalidationEvent::Inode {
                    ino: InodeId::new(2),
                    generation: 1,
                },
                InvalidationEvent::Inode {
                    ino: InodeId::new(3),
                    generation: 1,
                },
            ],
        ));
        assert_eq!(c.process_tick(2), 2);
        assert_eq!(c.pending_event_count(), 1);
        assert_eq!(c.process_tick(10), 1);
    }
}
