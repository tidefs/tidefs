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
    pub pages_invalidated: u64,
    pub coherency_conflicts: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmapRegistration {
    generation: u64,
    active: bool,
}

/// Mmap cluster coherency manager.
pub struct MmapCoherency {
    registrations: Mutex<BTreeMap<u64, MmapRegistration>>,
    processor: Mutex<FollowerInvalidationProcessor>,
    notifier: Arc<Mutex<Option<fuser::Notifier>>>,
    pub stats: MmapCoherencyStats,
}

impl MmapCoherency {
    pub fn new(notifier: Arc<Mutex<Option<fuser::Notifier>>>) -> Self {
        Self {
            registrations: Mutex::new(BTreeMap::new()),
            processor: Mutex::new(FollowerInvalidationProcessor::new()),
            notifier,
            stats: MmapCoherencyStats::new(),
        }
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

    pub fn invalidate_local_range(&self, ino: u64, offset: u64, length: u64) -> bool {
        if length == 0 || !self.is_registered(ino) {
            return false;
        }
        self.stats
            .coherency_conflicts
            .fetch_add(1, Ordering::Relaxed);
        self.stats.pages_invalidated.fetch_add(1, Ordering::Relaxed);
        notify_inode_range(&self.notifier, ino, offset, length);
        true
    }
}

fn notify_inode_range(
    notifier: &Arc<Mutex<Option<fuser::Notifier>>>,
    ino: u64,
    offset: u64,
    length: u64,
) {
    let Some((offset, length)) = fuse_inval_range(offset, length) else {
        return;
    };
    if let Ok(guard) = notifier.lock() {
        if let Some(ref n) = *guard {
            let _ = n.inval_inode(ino, offset, length);
        }
    }
}

fn fuse_inval_range(offset: u64, length: u64) -> Option<(i64, i64)> {
    if offset == 0 && length == 0 {
        return Some((0, -1));
    }
    if length == 0 {
        return None;
    }
    let offset = i64::try_from(offset).ok()?;
    let length = i64::try_from(length).ok()?;
    Some((offset, length))
}

struct MmapInvalidationSink<'a> {
    registrations: &'a Mutex<BTreeMap<u64, MmapRegistration>>,
    notifier: &'a Arc<Mutex<Option<fuser::Notifier>>>,
    stats: &'a MmapCoherencyStats,
}

impl InvalidationSink for MmapInvalidationSink<'_> {
    fn invalidate_inode(&mut self, ino: InodeId, generation: u64) {
        self.stats
            .invalidations_received
            .fetch_add(1, Ordering::Relaxed);
        let ino_u64 = ino.0;
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
            notify_inode_range(self.notifier, ino_u64, 0, 0);
        }
    }

    fn invalidate_entry(&mut self, _parent: InodeId, _name: &[u8]) {}
    fn invalidate_directory(&mut self, _ino: InodeId) {}
    fn invalidate_dataset(&mut self, _dataset: DatasetId) {}
    fn invalidate_range(&mut self, ino: InodeId, offset: u64, length: u64) {
        self.stats
            .invalidations_received
            .fetch_add(1, Ordering::Relaxed);
        let ino_u64 = ino.0;
        let should_invalidate = self
            .registrations
            .lock()
            .unwrap()
            .get(&ino_u64)
            .is_some_and(|entry| entry.active);
        if should_invalidate && fuse_inval_range(offset, length).is_some() {
            self.stats
                .coherency_conflicts
                .fetch_add(1, Ordering::Relaxed);
            self.stats.pages_invalidated.fetch_add(1, Ordering::Relaxed);
            notify_inode_range(self.notifier, ino_u64, offset, length);
        }
    }
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

    fn range_batch(ino: u64, offset: u64, length: u64) -> InvalidationBatch {
        InvalidationBatch::new(
            DatasetId::new(1),
            CommitGroupId::new(1),
            vec![InvalidationEvent::Range {
                ino: InodeId::new(ino),
                offset,
                length,
            }],
        )
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
    fn range_invalidation_triggers_for_registered_inode() {
        let c = new_coherency();
        c.register(42, 1);
        c.enqueue_batch(range_batch(42, 4096, 8192));
        let n = c.process_tick(10);
        assert_eq!(n, 1);
        let s = c.stats.snapshot();
        assert_eq!(s.invalidations_received, 1);
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn local_range_invalidation_tracks_registered_inode() {
        let c = new_coherency();
        c.register(42, 1);
        assert!(c.invalidate_local_range(42, 4096, 8192));
        let s = c.stats.snapshot();
        assert_eq!(s.coherency_conflicts, 1);
        assert_eq!(s.pages_invalidated, 1);
    }

    #[test]
    fn local_range_invalidation_ignores_unregistered_inode() {
        let c = new_coherency();
        assert!(!c.invalidate_local_range(42, 4096, 8192));
        let s = c.stats.snapshot();
        assert_eq!(s.coherency_conflicts, 0);
        assert_eq!(s.pages_invalidated, 0);
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
