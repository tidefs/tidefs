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

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
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
/// dirty/writeback pages are preserved (authority contract:
/// "Dirty and writeback pages must not be silently invalidated").
pub type DirtyStateCheck = Box<dyn Fn(u64) -> bool + Send + Sync>;

/// Mmap cluster coherency manager.
///
/// # Dirty/writeback preservation
///
/// When a [`DirtyStateCheck`] callback is set (via
/// [`MmapCoherency::set_dirty_check`]),
/// the invalidation sink consults it before sending
/// `FUSE_NOTIFY_INVAL_INODE`.  Inodes with dirty or writeback-pending
/// bytes are preserved; their page-cache entries are not invalidated, per
/// the authority contract in
/// `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`.
pub struct MmapCoherency {
    registrations: Mutex<BTreeMap<u64, MmapRegistration>>,
    processor: Mutex<FollowerInvalidationProcessor>,
    notifier: Arc<Mutex<Option<fuser::Notifier>>>,
    /// Optional callback to check whether an inode has dirty or
    /// writeback-pending bytes.  When set and the callback returns
    /// `true`, mmap invalidation for that inode is skipped or deferred
    /// until the dirty state is resolved.
    dirty_check: Mutex<Option<DirtyStateCheck>>,
    pub stats: MmapCoherencyStats,
}

impl MmapCoherency {
    pub fn new(notifier: Arc<Mutex<Option<fuser::Notifier>>>) -> Self {
        Self {
            registrations: Mutex::new(BTreeMap::new()),
            processor: Mutex::new(FollowerInvalidationProcessor::new()),
            notifier,
            dirty_check: Mutex::new(None),
            stats: MmapCoherencyStats::new(),
        }
    }

    /// Install a dirty-state check callback.
    ///
    /// When set, the invalidation sink calls this callback before sending
    /// `FUSE_NOTIFY_INVAL_INODE`.  If the callback returns `true` (inode
    /// has dirty or writeback-pending bytes), the invalidation is skipped.
    pub fn set_dirty_check(&self, check: Option<DirtyStateCheck>) {
        *self.dirty_check.lock().unwrap() = check;
    }

    pub fn register(&self, ino: u64, generation: u64) {
        let mut regs = self.registrations.lock().unwrap();
        let entry = regs.entry(ino).or_insert(MmapRegistration {
            generation: 0,
            active: false,
        });
        entry.generation = generation;
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

    pub fn process_tick(&self, event_budget: usize) -> usize {
        let mut sink = MmapInvalidationSink {
            registrations: &self.registrations,
            notifier: &self.notifier,
            dirty_check: &self.dirty_check,
            stats: &self.stats,
        };
        self.processor
            .lock()
            .unwrap()
            .process_tick(&mut sink, event_budget)
    }

    pub fn pending_event_count(&self) -> usize {
        self.processor.lock().unwrap().pending_event_count()
    }
}

struct MmapInvalidationSink<'a> {
    registrations: &'a Mutex<BTreeMap<u64, MmapRegistration>>,
    notifier: &'a Arc<Mutex<Option<fuser::Notifier>>>,
    /// Reference to the optional dirty-state check callback owned by
    /// [`MmapCoherency`].  When the callback is set and returns `true`,
    /// invalidation for dirty/writeback inodes is skipped.
    dirty_check: &'a Mutex<Option<DirtyStateCheck>>,
    stats: &'a MmapCoherencyStats,
}

impl InvalidationSink for MmapInvalidationSink<'_> {
    fn invalidate_inode(&mut self, ino: InodeId, generation: u64) {
        self.stats
            .invalidations_received
            .fetch_add(1, Ordering::Relaxed);
        let ino_u64 = ino.0;

        // Dirty/writeback guard: consult the optional dirty_check callback.
        // When the inode has dirty or writeback-pending bytes, skip the
        // invalidation to preserve dirty/writeback pages per the authority
        // contract in docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md.
        let is_dirty = self
            .dirty_check
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|check| check(ino_u64));
        if is_dirty {
            self.stats
                .dirty_invalidations_preserved
                .fetch_add(1, Ordering::Relaxed);
            return;
        }

        let should_invalidate = {
            let mut regs = self.registrations.lock().unwrap();
            match regs.get_mut(&ino_u64) {
                Some(ref mut entry) if entry.active && generation > entry.generation => {
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
            if let Ok(guard) = self.notifier.lock() {
                if let Some(ref n) = *guard {
                    let _ = n.inval_inode(ino_u64, 0, -1);
                }
            }
        }
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
        MmapCoherency::new(Arc::new(Mutex::new(None)))
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
    fn dirty_check_preserves_dirty_inode_invalidation_state() {
        let c = new_coherency();
        c.register(42, 1);
        c.set_dirty_check(Some(Box::new(|ino| ino == 42)));

        c.enqueue_batch(batch(42, 2));
        assert_eq!(c.process_tick(10), 1);

        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.dirty_invalidations_preserved, 1);
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);

        let regs = c.registrations.lock().unwrap();
        let registration = regs.get(&42).expect("registered inode remains tracked");
        assert!(registration.active);
        assert_eq!(registration.generation, 1);
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
    fn deregistered_inode_ignored() {
        let c = new_coherency();
        c.register(42, 1);
        c.deregister(42);
        c.enqueue_batch(batch(42, 2));
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
