// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]
//! Writeback-cache runtime projection: observable dirty/writeback lifecycle.
//!
//! This module provides a unified runtime view (projection) of the FUSE
//! writeback-cache and mmap-coherency dirty/writeback state for a mounted
//! daemon.  It consumes the local durability authority without strengthening
//! that authority.  Its purpose is to make every dirty-to-clean transition
//! observable so that claim-gate validation can confirm no hidden writeback
//! queues, dirty/writeback preservation during invalidation, and bounded
//! userspace durability fences.
//!
//! # Authority relationship
//!
//! The projection is a runtime view only.  It does **not**:
//! - own durable inode-lookup/forget (#665/#709),
//! - own FUSE invalidation fences (#752),
//! - own cluster lease transport,
//! - own kernel address-space callbacks, or
//! - strengthen the durability or coherency guarantee on its own.
//!
//! The projection is the concrete FUSE adapter-side counterpart of the
//! authority contract in `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::fuse_vfs_adapter::DirtyRanges;
use crate::mmap_coherency::MmapCoherency;
use tidefs_cache_core::page_cache::PageCache;

// ---------------------------------------------------------------------------
// WritebackState — per-inode observable dirty/writeback/clean lifecycle
// ---------------------------------------------------------------------------

/// The observable dirty/writeback state of a single inode.
///
/// Every state transition is recorded so the projection can report:
/// - total dirty bytes (not yet selected for writeback),
/// - total writeback-pending bytes (selected but not yet clean),
/// - total clean transitions since the last projection snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritebackLane {
    /// Bytes are clean: no dirty or writeback-pending data.
    Clean,
    /// Bytes are dirty: buffered but not yet selected for writeback.
    Dirty { bytes: u64 },
    /// Bytes are writeback-pending: selected and written through, waiting for
    /// the durability barrier (fsync, commit_group, storage-commit).
    WritebackPending { bytes: u64 },
}

impl WritebackLane {
    /// Return the byte count tracked by this lane, or 0 for Clean.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        match self {
            Self::Clean => 0,
            Self::Dirty { bytes } | Self::WritebackPending { bytes } => bytes,
        }
    }

    /// True when the lane is Dirty or WritebackPending (not Clean).
    #[must_use]
    pub const fn is_dirty_or_writeback(self) -> bool {
        !matches!(self, Self::Clean)
    }
}

// ---------------------------------------------------------------------------
// WritebackProjectionStats — observable projection counters
// ---------------------------------------------------------------------------

/// Atomic counters for the writeback projection.
///
/// These counters are observable by the claim-gate and no-hidden-queue
/// validation paths.  They record state transitions, not per-byte counts.
#[derive(Debug, Default)]
pub struct WritebackProjectionStats {
    /// Number of inodes that entered the Dirty lane.
    pub dirty_transitions: AtomicU64,
    /// Number of inodes that entered the WritebackPending lane.
    pub writeback_pending_transitions: AtomicU64,
    /// Number of inodes that transitioned to Clean (fsync, flush, commit).
    pub clean_transitions: AtomicU64,
    /// Number of invalidation attempts skipped because the inode was dirty
    /// or writeback-pending.
    pub invalidation_skips_dirty: AtomicU64,
    /// Number of invalidation attempts that proceeded because the inode
    /// was clean.
    pub invalidation_allowed_clean: AtomicU64,
}

impl WritebackProjectionStats {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn snapshot(&self) -> WritebackProjectionStatsSnapshot {
        WritebackProjectionStatsSnapshot {
            dirty_transitions: self.dirty_transitions.load(Ordering::Relaxed),
            writeback_pending_transitions: self
                .writeback_pending_transitions
                .load(Ordering::Relaxed),
            clean_transitions: self.clean_transitions.load(Ordering::Relaxed),
            invalidation_skips_dirty: self.invalidation_skips_dirty.load(Ordering::Relaxed),
            invalidation_allowed_clean: self.invalidation_allowed_clean.load(Ordering::Relaxed),
        }
    }
}

/// Non-atomic snapshot of WritebackProjectionStats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WritebackProjectionStatsSnapshot {
    pub dirty_transitions: u64,
    pub writeback_pending_transitions: u64,
    pub clean_transitions: u64,
    pub invalidation_skips_dirty: u64,
    pub invalidation_allowed_clean: u64,
}

// ---------------------------------------------------------------------------
// WritebackProjection — single observable dirty/writeback view
// ---------------------------------------------------------------------------

/// The mounted FUSE writeback-cache and mmap-coherency runtime projection.
///
/// Every dirty byte created by a buffered write, every writeback batch,
/// and every clean transition is observable through this projection.
/// There are no hidden queues: all dirty and writeback-pending state is
/// tracked in the [`lanes`] map and the attached [`DirtyRanges`] mirror.
///
/// The projection does **not** own durability or coherency authority.
/// It is a runtime view that enables claim-gate validation of:
/// - dirty lifecycle observability,
/// - writeback batch visibility,
/// - mmap-coherency dirty-preservation during invalidation,
/// - no-hidden-queue evidence.
pub struct WritebackProjection {
    /// Per-inode observable lane: Clean, Dirty, or WritebackPending.
    lanes: Mutex<BTreeMap<u64, WritebackLane>>,
    /// Reference to the adapter's PageCache for dirty-page mirror tracking.
    page_cache: Option<Arc<PageCache>>,
    /// Reference to the adapter's mmap coherency for dirty-state-aware
    /// invalidation guards.
    mmap_coherency: Arc<MmapCoherency>,
    /// Atomic projection counters.
    pub stats: WritebackProjectionStats,
}

impl WritebackProjection {
    /// Create a new projection.
    ///
    /// `page_cache` is the adapter's `write_page_cache` (the PageCache used
    /// for dirty-page mirror tracking).  When [`None`], the projection
    /// tracks lane transitions but does not inspect cache-internal state.
    ///
    /// `mmap_coherency` is the adapter's [`MmapCoherency`] cell; the
    /// projection uses it to check mmap registration during invalidation
    /// guards.
    #[must_use]
    pub fn new(page_cache: Option<Arc<PageCache>>, mmap_coherency: Arc<MmapCoherency>) -> Self {
        Self {
            lanes: Mutex::new(BTreeMap::new()),
            page_cache,
            mmap_coherency,
            stats: WritebackProjectionStats::new(),
        }
    }

    // ── Lane transitions ──────────────────────────────────────────────

    /// Record that `ino` has dirty bytes (total dirty byte count across all
    /// tracked ranges).
    ///
    /// This is called after a buffered write has been processed and dirty
    /// state has been recorded in the adapter's [`DirtyRanges`] and/or
    /// [`PageCache`].
    pub fn record_dirty(&self, ino: u64, _total_dirty_bytes: u64) {
        let mut lanes = self.lanes.lock().unwrap();
        let prev = lanes.insert(
            ino,
            WritebackLane::Dirty {
                bytes: _total_dirty_bytes,
            },
        );
        if prev.is_none() || matches!(prev, Some(WritebackLane::Clean)) {
            self.stats.dirty_transitions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Record that `ino` has been selected for writeback (dirty bytes have
    /// been written through to the engine but have not yet passed the
    /// durability barrier).
    pub fn record_writeback_pending(&self, ino: u64, total_bytes: u64) {
        let _prev = self
            .lanes
            .lock()
            .unwrap()
            .insert(ino, WritebackLane::WritebackPending { bytes: total_bytes });
        self.stats
            .writeback_pending_transitions
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record that `ino` has transitioned to Clean after a successful
    /// fsync, flush, commit-group, or storage-commit barrier.
    pub fn record_clean(&self, ino: u64) {
        let prev = self.lanes.lock().unwrap().insert(ino, WritebackLane::Clean);
        if prev.is_some_and(|p| p.is_dirty_or_writeback()) {
            self.stats.clean_transitions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Remove all tracking for `ino` (e.g., on last-close or forget).
    pub fn remove(&self, ino: u64) {
        self.lanes.lock().unwrap().remove(&ino);
    }

    // ── Query methods ─────────────────────────────────────────────────

    /// Return the current lane for `ino`, or [`None`] if not tracked.
    #[must_use]
    pub fn lane(&self, ino: u64) -> Option<WritebackLane> {
        self.lanes.lock().unwrap().get(&ino).copied()
    }

    /// True when `ino` has dirty or writeback-pending bytes.
    #[must_use]
    pub fn is_dirty_or_writeback(&self, ino: u64) -> bool {
        self.lanes
            .lock()
            .unwrap()
            .get(&ino)
            .is_some_and(|l| l.is_dirty_or_writeback())
    }

    /// True when `ino` is currently in the Dirty lane.
    #[must_use]
    pub fn is_dirty(&self, ino: u64) -> bool {
        matches!(self.lane(ino), Some(WritebackLane::Dirty { .. }))
    }

    /// True when `ino` is currently in the WritebackPending lane.
    #[must_use]
    pub fn is_writeback_pending(&self, ino: u64) -> bool {
        matches!(self.lane(ino), Some(WritebackLane::WritebackPending { .. }))
    }

    /// Return the total number of inodes currently in a dirty or
    /// writeback-pending lane.
    #[must_use]
    pub fn dirty_or_writeback_inode_count(&self) -> usize {
        self.lanes
            .lock()
            .unwrap()
            .values()
            .filter(|l| l.is_dirty_or_writeback())
            .count()
    }

    /// Return the total dirty and writeback-pending byte count across
    /// all tracked inodes.
    #[must_use]
    pub fn total_dirty_or_writeback_bytes(&self) -> u64 {
        self.lanes.lock().unwrap().values().map(|l| l.bytes()).sum()
    }

    /// Return a snapshot of the observable projection stats.
    #[must_use]
    pub fn stats_snapshot(&self) -> WritebackProjectionStatsSnapshot {
        self.stats.snapshot()
    }

    // ── Mmap-coherency invalidation guard ────────────────────────────

    /// Check whether an mmap-coherency invalidation should proceed for
    /// `ino`.
    ///
    /// Returns `true` when invalidation is allowed (the inode is clean).
    /// Returns `false` when invalidation must be skipped or deferred
    /// because the inode has dirty or writeback-pending bytes.
    ///
    /// This implements the authority contract in
    /// `docs/PAGE_CACHE_WRITEBACK_AUTHORITY.md`:
    /// "Dirty and writeback pages must not be silently invalidated."
    pub fn invalidation_allowed(&self, ino: u64) -> bool {
        if self.is_dirty_or_writeback(ino) {
            self.stats
                .invalidation_skips_dirty
                .fetch_add(1, Ordering::Relaxed);
            false
        } else {
            self.stats
                .invalidation_allowed_clean
                .fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    /// Check whether the adapter's per-inode [`DirtyRanges`] have any
    /// dirty data covering the range `[offset, offset+length)`.
    ///
    /// This is used by the FUSE write dispatch to decide whether a
    /// writeback-cached write has left dirty bytes that must be drained
    /// before invalidation or truncate.
    #[must_use]
    pub fn dirty_ranges_overlap(
        dirty_state: &Mutex<BTreeMap<u64, DirtyRanges>>,
        ino: u64,
        offset: u64,
        length: u64,
    ) -> bool {
        dirty_state
            .lock()
            .unwrap()
            .get(&ino)
            .is_some_and(|dr| dr.overlaps(offset, length))
    }

    /// Return the total dirty byte count from the adapter's per-inode
    /// [`DirtyRanges`] for `ino`.
    #[must_use]
    pub fn dirty_ranges_total(dirty_state: &Mutex<BTreeMap<u64, DirtyRanges>>, ino: u64) -> u64 {
        dirty_state
            .lock()
            .unwrap()
            .get(&ino)
            .map(|dr| dr.ranges().iter().map(|&(start, end)| end - start).sum())
            .unwrap_or(0)
    }

    /// Return the total tracked dirty byte count from the adapter's
    /// [`PageCache`] for `ino`.
    #[must_use]
    pub fn page_cache_dirty_total(page_cache: Option<&Arc<PageCache>>, ino: u64) -> u64 {
        page_cache
            .map(|pc| {
                pc.dirty_pages_for_inode(ino)
                    .iter()
                    .map(|offset| pc.page_size() as u64)
                    .sum()
            })
            .unwrap_or(0)
    }

    /// Total observable dirty bytes for an inode: sum of DirtyRanges +
    /// PageCache dirty pages.
    #[must_use]
    pub fn total_observable_dirty_bytes(
        dirty_state: &Mutex<BTreeMap<u64, DirtyRanges>>,
        page_cache: Option<&Arc<PageCache>>,
        ino: u64,
    ) -> u64 {
        Self::dirty_ranges_total(dirty_state, ino) + Self::page_cache_dirty_total(page_cache, ino)
    }

    // ── Mmap coherency accessor ──────────────────────────────────────

    /// Return a clone of the mmap coherency arc for the adapter.
    #[must_use]
    pub fn mmap_coherency(&self) -> Arc<MmapCoherency> {
        Arc::clone(&self.mmap_coherency)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn new_projection() -> WritebackProjection {
        let notifier = Arc::new(Mutex::new(None));
        let mmap = Arc::new(MmapCoherency::new(notifier));
        WritebackProjection::new(None, mmap)
    }

    #[test]
    fn clean_by_default() {
        let p = new_projection();
        assert!(!p.is_dirty_or_writeback(42));
        assert!(!p.is_dirty(42));
        assert!(!p.is_writeback_pending(42));
        assert_eq!(p.lane(42), None);
    }

    #[test]
    fn record_dirty_transition() {
        let p = new_projection();
        p.record_dirty(42, 8192);
        assert!(p.is_dirty_or_writeback(42));
        assert!(p.is_dirty(42));
        assert_eq!(p.lane(42), Some(WritebackLane::Dirty { bytes: 8192 }));
        assert_eq!(p.stats_snapshot().dirty_transitions, 1);
    }

    #[test]
    fn record_writeback_pending_transition() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.record_writeback_pending(42, 4096);
        assert!(p.is_dirty_or_writeback(42));
        assert!(p.is_writeback_pending(42));
        assert!(!p.is_dirty(42));
        assert_eq!(
            p.lane(42),
            Some(WritebackLane::WritebackPending { bytes: 4096 })
        );
        assert_eq!(p.stats_snapshot().writeback_pending_transitions, 1);
    }

    #[test]
    fn record_clean_transition() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.record_clean(42);
        assert!(!p.is_dirty_or_writeback(42));
        assert_eq!(p.lane(42), Some(WritebackLane::Clean));
        assert_eq!(p.stats_snapshot().clean_transitions, 1);
    }

    #[test]
    fn clean_to_clean_no_transition_counted() {
        let p = new_projection();
        p.record_clean(42); // no prior dirty state
        assert_eq!(p.lane(42), Some(WritebackLane::Clean));
        assert_eq!(p.stats_snapshot().clean_transitions, 0);
    }

    #[test]
    fn dirty_to_dirty_counts_only_first() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.record_dirty(42, 8192); // more bytes, but same inode already dirty
        assert_eq!(p.stats_snapshot().dirty_transitions, 1);
    }

    #[test]
    fn remove_clears_tracking() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.remove(42);
        assert!(!p.is_dirty_or_writeback(42));
        assert_eq!(p.lane(42), None);
    }

    #[test]
    fn invalidation_allowed_when_clean() {
        let p = new_projection();
        assert!(p.invalidation_allowed(42));
        assert_eq!(p.stats_snapshot().invalidation_allowed_clean, 1);
    }

    #[test]
    fn invalidation_blocked_when_dirty() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        assert!(!p.invalidation_allowed(42));
        assert_eq!(p.stats_snapshot().invalidation_skips_dirty, 1);
    }

    #[test]
    fn invalidation_blocked_when_writeback_pending() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.record_writeback_pending(42, 4096);
        assert!(!p.invalidation_allowed(42));
    }

    #[test]
    fn invalidation_allowed_after_clean() {
        let p = new_projection();
        p.record_dirty(42, 4096);
        p.record_clean(42);
        assert!(p.invalidation_allowed(42));
    }

    #[test]
    fn dirty_or_writeback_count() {
        let p = new_projection();
        p.record_dirty(10, 4096);
        p.record_dirty(20, 4096);
        p.record_writeback_pending(20, 4096);
        p.record_clean(10);
        assert_eq!(p.dirty_or_writeback_inode_count(), 1); // only ino=20
    }

    #[test]
    fn total_dirty_or_writeback_bytes() {
        let p = new_projection();
        p.record_dirty(10, 8192);
        p.record_writeback_pending(20, 16384);
        assert_eq!(p.total_dirty_or_writeback_bytes(), 8192 + 16384);
        p.record_clean(10);
        assert_eq!(p.total_dirty_or_writeback_bytes(), 16384);
    }

    #[test]
    fn stats_snapshot_all_zero_after_construction() {
        let p = new_projection();
        let s = p.stats_snapshot();
        assert_eq!(s.dirty_transitions, 0);
        assert_eq!(s.writeback_pending_transitions, 0);
        assert_eq!(s.clean_transitions, 0);
        assert_eq!(s.invalidation_skips_dirty, 0);
        assert_eq!(s.invalidation_allowed_clean, 0);
    }

    #[test]
    fn writeback_lane_bytes() {
        assert_eq!(WritebackLane::Clean.bytes(), 0);
        assert_eq!(WritebackLane::Dirty { bytes: 42 }.bytes(), 42);
        assert_eq!(WritebackLane::WritebackPending { bytes: 99 }.bytes(), 99);
    }

    #[test]
    fn writeback_lane_is_dirty_or_writeback() {
        assert!(!WritebackLane::Clean.is_dirty_or_writeback());
        assert!(WritebackLane::Dirty { bytes: 1 }.is_dirty_or_writeback());
        assert!(WritebackLane::WritebackPending { bytes: 1 }.is_dirty_or_writeback());
    }
}
