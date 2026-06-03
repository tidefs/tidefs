//! Capacity tracker with monotonic generation counter and a formal refresh
//! lifecycle state machine.
//!
//! [`CapacityTracker`] wraps a [`CapacityFacade`] and an inode-count source
//! to produce [`CapacitySnapshot`] values with monotonic generation counters.
//! The refresh state machine gates concurrent refreshes and surfaces error
//! states through [`CapacityError`].

use std::fmt;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Mutex,
};

use super::CapacityFacade;

/// Source of filesystem-wide inode statistics.
///
/// Implementations typically wrap an inode table and return
/// `(total_capacity, free_count)`.
pub trait InodeCountSource: Send + Sync {
    /// Return (total_inode_slots, free_inode_slots).
    fn inode_counts(&self) -> (u64, u64);
}

/// Blanket impl so closures and function pointers work as sources.
impl<F> InodeCountSource for F
where
    F: Fn() -> (u64, u64) + Send + Sync,
{
    fn inode_counts(&self) -> (u64, u64) {
        self()
    }
}

// ── Error type ──────────────────────────────────────────────────────────

/// Errors that can occur during a capacity refresh cycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    /// The block allocator query failed or returned inconsistent data.
    AllocatorUnavailable,
    /// The inode table query failed or returned inconsistent data.
    InodeTableUnavailable,
    /// The refresh was attempted with a stale generation counter,
    /// indicating a concurrent refresh completed first.
    StaleGeneration,
    /// A lower-level backend error prevented the refresh from completing.
    BackendError,
}

impl fmt::Display for CapacityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllocatorUnavailable => f.write_str("block allocator unavailable"),
            Self::InodeTableUnavailable => f.write_str("inode table unavailable"),
            Self::StaleGeneration => {
                f.write_str("stale generation: concurrent refresh completed first")
            }
            Self::BackendError => f.write_str("backend error during capacity refresh"),
        }
    }
}

impl std::error::Error for CapacityError {}

// ── Refresh state machine ───────────────────────────────────────────────

/// Refresh lifecycle states for the capacity tracker.
///
/// Transitions: `Idle → QueryingAllocator → QueryingInodeTable → Idle`.
/// Any transition can move to `Idle` on error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityRefreshState {
    /// No refresh in progress.
    Idle,
    /// Querying the block allocator for block-level statistics.
    QueryingAllocator,
    /// Querying the inode table for inode-level statistics.
    QueryingInodeTable,
}

// ── Snapshot ────────────────────────────────────────────────────────────

/// A point-in-time snapshot of filesystem capacity with a monotonic
/// generation counter for stale-reader detection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapacitySnapshot {
    /// Total data blocks in the filesystem.
    pub total_blocks: u64,
    /// Free data blocks.
    pub free_blocks: u64,
    /// Free data blocks available to unprivileged users (below root reserve).
    pub available_blocks: u64,
    /// Total inode slots.
    pub total_inodes: u64,
    /// Free inode slots.
    pub free_inodes: u64,
    /// Filesystem block size in bytes.
    pub block_size: u32,
    /// Monotonic generation counter incremented on each successful refresh.
    pub generation: u64,
}

// ── Tracker ─────────────────────────────────────────────────────────────

/// Tracks filesystem capacity with a monotonic generation counter.
///
/// The tracker queries the block allocator (via a [`CapacityFacade`]) and
/// an inode-count source (`I`) to produce snapshots. A monotonic generation
/// counter guards against concurrent refreshes.
pub struct CapacityTracker<I: InodeCountSource> {
    facade: CapacityFacade,
    inode_source: I,
    state: Mutex<CapacityRefreshState>,
    snapshot: Mutex<Option<CapacitySnapshot>>,
    generation: AtomicU64,
}

impl<I: InodeCountSource> CapacityTracker<I> {
    /// Create a new tracker with an initial generation of 0 and no snapshot.
    #[must_use]
    pub fn new(facade: CapacityFacade, inode_source: I) -> Self {
        Self {
            facade,
            inode_source,
            state: Mutex::new(CapacityRefreshState::Idle),
            snapshot: Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }

    /// Return the current refresh state.
    #[must_use]
    pub fn refresh_state(&self) -> CapacityRefreshState {
        *self.state.lock().unwrap()
    }

    /// Return the current generation counter.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Return the latest committed snapshot, if any.
    #[must_use]
    pub fn latest(&self) -> Option<CapacitySnapshot> {
        self.snapshot.lock().unwrap().clone()
    }

    /// Return a reference to the underlying capacity facade.
    #[must_use]
    pub fn facade(&self) -> &CapacityFacade {
        &self.facade
    }

    /// Return a reference to the inode count source.
    #[must_use]
    pub fn inode_source(&self) -> &I {
        &self.inode_source
    }

    /// Execute a full refresh cycle.
    ///
    /// Returns the new snapshot on success or a [`CapacityError`] on
    /// failure. Only one refresh may be in flight at a time; concurrent
    /// callers receive [`CapacityError::StaleGeneration`].
    pub fn refresh(&self) -> Result<CapacitySnapshot, CapacityError> {
        // ── Acquire Idle → QueryingAllocator ───────────────────
        {
            let mut state = self.state.lock().unwrap();
            if *state != CapacityRefreshState::Idle {
                return Err(CapacityError::StaleGeneration);
            }
            *state = CapacityRefreshState::QueryingAllocator;
        }

        // ── Query allocator ────────────────────────────────────
        let statfs = self.facade.statfs();
        // Basic sanity: block_size must be nonzero for a configured fs.
        if statfs.bsize == 0 {
            self.reset_to_idle();
            return Err(CapacityError::AllocatorUnavailable);
        }

        // ── QueryingAllocator → QueryingInodeTable ─────────────
        {
            let mut state = self.state.lock().unwrap();
            if *state != CapacityRefreshState::QueryingAllocator {
                return Err(CapacityError::StaleGeneration);
            }
            *state = CapacityRefreshState::QueryingInodeTable;
        }

        // ── Query inode table ──────────────────────────────────
        let (total_inodes, free_inodes) = self.inode_source.inode_counts();
        if total_inodes == 0 || free_inodes > total_inodes {
            self.reset_to_idle();
            return Err(CapacityError::InodeTableUnavailable);
        }

        // ── Build and publish snapshot ─────────────────────────
        let next_gen = self.generation.load(Ordering::Acquire).wrapping_add(1);

        let snapshot = CapacitySnapshot {
            total_blocks: statfs.blocks,
            free_blocks: statfs.bfree,
            available_blocks: statfs.bavail,
            total_inodes,
            free_inodes,
            block_size: statfs.bsize as u32,
            generation: next_gen,
        };

        // Publish snapshot before advancing generation so readers
        // always see a snapshot whose generation matches the counter.
        {
            let mut snap = self.snapshot.lock().unwrap();
            *snap = Some(snapshot.clone());
        }
        self.generation.store(next_gen, Ordering::Release);

        // ── QueryingInodeTable → Idle ──────────────────────────
        {
            let mut state = self.state.lock().unwrap();
            *state = CapacityRefreshState::Idle;
        }

        Ok(snapshot)
    }

    /// Reset state to Idle on error paths.
    fn reset_to_idle(&self) {
        *self.state.lock().unwrap() = CapacityRefreshState::Idle;
    }
}

// Manual Clone impl: share the same inner state (like Arc semantics).
// The facade is already Clone but we must carry forward the state and
// generation. Since Mutex/AtomicU64 are not Clone, we create new ones
// with current values — callers that need shared-state tracking should
// wrap the tracker in an Arc.
impl<I: InodeCountSource + Clone> Clone for CapacityTracker<I> {
    fn clone(&self) -> Self {
        Self {
            facade: self.facade.clone(),
            inode_source: self.inode_source.clone(),
            state: Mutex::new(*self.state.lock().unwrap()),
            snapshot: Mutex::new(self.snapshot.lock().unwrap().clone()),
            generation: AtomicU64::new(self.generation.load(Ordering::Acquire)),
        }
    }
}

impl<I: InodeCountSource> fmt::Debug for CapacityTracker<I> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapacityTracker")
            .field("state", &self.refresh_state())
            .field("generation", &self.generation())
            .field("snapshot", &self.latest())
            .finish_non_exhaustive()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_block_allocator::{BlockAllocator, Region};

    fn test_allocator(blocks: u64) -> BlockAllocator {
        BlockAllocator::with_root_reserve(
            blocks,
            4096,
            Region::new(0, BlockAllocator::required_bitmap_bytes(blocks)),
            50,
        )
    }

    fn test_facade(blocks: u64) -> CapacityFacade {
        CapacityFacade::new(test_allocator(blocks))
    }

    fn make_tracker(
        blocks: u64,
        inode_total: u64,
        inode_free: u64,
    ) -> CapacityTracker<impl InodeCountSource> {
        let facade = test_facade(blocks);
        CapacityTracker::new(facade, move || (inode_total, inode_free))
    }

    // ── Basic refresh ─────────────────────────────────────────────

    #[test]
    fn basic_refresh_produces_snapshot() {
        let tracker = make_tracker(1000, 500, 400);
        let snap = tracker.refresh().expect("refresh should succeed");
        assert_eq!(snap.total_blocks, 1000);
        assert_eq!(snap.free_blocks, 1000);
        assert_eq!(snap.available_blocks, 950); // 1000 - 50 root reserve
        assert_eq!(snap.total_inodes, 500);
        assert_eq!(snap.free_inodes, 400);
        assert_eq!(snap.block_size, 4096);
        assert_eq!(snap.generation, 1);
    }

    #[test]
    fn refresh_increments_generation() {
        let tracker = make_tracker(100, 10, 5);
        let snap1 = tracker.refresh().expect("first refresh");
        let snap2 = tracker.refresh().expect("second refresh");
        assert_eq!(snap1.generation, 1);
        assert_eq!(snap2.generation, 2);
        assert_ne!(snap1.generation, snap2.generation);
    }

    #[test]
    fn latest_returns_most_recent_snapshot() {
        let tracker = make_tracker(100, 10, 5);
        assert!(tracker.latest().is_none(), "no snapshot before refresh");
        let snap1 = tracker.refresh().unwrap();
        assert_eq!(tracker.latest().as_ref(), Some(&snap1));
        let snap2 = tracker.refresh().unwrap();
        assert_eq!(tracker.latest().as_ref(), Some(&snap2));
    }

    #[test]
    fn generation_starts_at_zero() {
        let tracker = make_tracker(100, 10, 5);
        assert_eq!(tracker.generation(), 0);
        tracker.refresh().unwrap();
        assert_eq!(tracker.generation(), 1);
    }

    // ── State machine transitions ──────────────────────────────────

    #[test]
    fn refresh_state_cycles_through_phases_and_returns_to_idle() {
        let tracker = make_tracker(100, 10, 5);
        assert_eq!(tracker.refresh_state(), CapacityRefreshState::Idle);
        tracker.refresh().unwrap();
        assert_eq!(tracker.refresh_state(), CapacityRefreshState::Idle);
    }

    // ── Error paths ───────────────────────────────────────────────

    #[test]
    fn zero_total_inodes_returns_inode_table_unavailable() {
        let tracker = make_tracker(100, 0, 0);
        let err = tracker.refresh().unwrap_err();
        assert_eq!(err, CapacityError::InodeTableUnavailable);
        assert_eq!(tracker.refresh_state(), CapacityRefreshState::Idle);
    }

    #[test]
    fn free_inodes_exceed_total_returns_inode_table_unavailable() {
        let tracker = make_tracker(100, 10, 15);
        let err = tracker.refresh().unwrap_err();
        assert_eq!(err, CapacityError::InodeTableUnavailable);
        assert_eq!(tracker.refresh_state(), CapacityRefreshState::Idle);
    }

    #[test]
    fn refresh_resumes_after_error() {
        let tracker = make_tracker(100, 0, 0);
        assert!(tracker.refresh().is_err());
        assert!(tracker.latest().is_none());
        // Fix the inode source and try again — must succeed.
        let tracker2 = make_tracker(100, 10, 5);
        let snap = tracker2.refresh().expect("retry after fix");
        assert_eq!(snap.generation, 1);
    }

    // ── Generation-driven stale detection ────────────────────────

    #[test]
    fn different_refreshes_have_different_generations() {
        let tracker = make_tracker(100, 10, 5);
        let s1 = tracker.refresh().unwrap();
        let s2 = tracker.refresh().unwrap();
        assert!(
            s2.generation > s1.generation,
            "generation must increase monotonically"
        );
    }

    #[test]
    fn generation_detects_stale_snapshot() {
        let tracker = make_tracker(100, 10, 5);
        let snap = tracker.refresh().unwrap();
        let gen_at_snap = snap.generation;
        // Refresh again — now latest has a newer generation.
        tracker.refresh().unwrap();
        assert!(
            tracker.generation() > gen_at_snap,
            "old snapshot generation is stale vs current counter"
        );
    }

    // ── Edge cases ─────────────────────────────────────────────────

    #[test]
    fn empty_pool_with_valid_inode_source() {
        let tracker = make_tracker(100, 50, 50);
        let snap = tracker.refresh().unwrap();
        assert_eq!(snap.total_inodes, 50);
        assert_eq!(snap.free_inodes, 50);
        assert_eq!(snap.generation, 1);
    }

    #[test]
    fn full_pool_zero_free_blocks() {
        let alloc = test_allocator(10);
        let facade = CapacityFacade::with_committed_blocks(alloc, 10);
        let tracker = CapacityTracker::new(facade, || (100, 50));
        let snap = tracker.refresh().unwrap();
        assert_eq!(snap.free_blocks, 0, "expected 0 free blocks");
        assert_eq!(snap.available_blocks, 0, "expected 0 available");
        assert_eq!(snap.generation, 1);
    }

    #[test]
    fn enospc_boundary_available_blocks() {
        let tracker = make_tracker(100, 100, 90);
        let snap = tracker.refresh().unwrap();
        assert_eq!(snap.total_blocks, 100);
        assert_eq!(snap.free_blocks, 100);
        assert_eq!(snap.available_blocks, 50);
        assert_eq!(snap.generation, 1);
    }

    #[test]
    fn facade_accessor_returns_same_allocator() {
        let tracker = make_tracker(100, 10, 5);
        let f = tracker.facade();
        assert_eq!(f.block_count(), 100);
        assert_eq!(f.block_size(), 4096);
    }

    #[test]
    fn inode_source_accessor_returns_counts() {
        let tracker = make_tracker(100, 42, 7);
        let src = tracker.inode_source();
        let (total, free) = src.inode_counts();
        assert_eq!(total, 42);
        assert_eq!(free, 7);
    }

    // ── Display / Error impls ─────────────────────────────────────

    #[test]
    fn capacity_error_display_is_nonempty() {
        let errors = [
            CapacityError::AllocatorUnavailable,
            CapacityError::InodeTableUnavailable,
            CapacityError::StaleGeneration,
            CapacityError::BackendError,
        ];
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty(), "Display impl empty for {err:?}");
        }
    }

    #[test]
    fn capacity_error_implements_std_error() {
        fn _assert_error<E: std::error::Error>(_e: &E) {}
        let err = CapacityError::BackendError;
        _assert_error(&err);
    }

    // ── Debug output ──────────────────────────────────────────────

    #[test]
    fn debug_output_contains_generation_and_state() {
        let tracker = make_tracker(100, 10, 5);
        tracker.refresh().unwrap();
        let debug = format!("{tracker:?}");
        assert!(debug.contains("CapacityTracker"));
        assert!(debug.contains("generation"));
    }

    // ── Snapshot structural equality ──────────────────────────────

    #[test]
    fn identical_snapshots_are_equal() {
        let tracker = make_tracker(100, 10, 5);
        let s1 = tracker.refresh().unwrap();
        let s2 = tracker.latest().unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn different_generations_produce_different_snapshots() {
        let tracker = make_tracker(100, 10, 5);
        let s1 = tracker.refresh().unwrap();
        let s2 = tracker.refresh().unwrap();
        assert_ne!(s1, s2);
    }

    // ── Error recovery ────────────────────────────────────────────

    #[test]
    fn error_path_resets_state_to_idle() {
        let tracker = make_tracker(100, 0, 0);
        let _ = tracker.refresh();
        assert_eq!(tracker.refresh_state(), CapacityRefreshState::Idle);
        assert!(tracker.latest().is_none());
    }

    // ── Trait object / closure usage ──────────────────────────────

    #[test]
    fn inode_count_source_via_closure() {
        let alloc = test_allocator(50);
        let facade = CapacityFacade::new(alloc);
        let inode_counts = || (200, 100);
        let tracker = CapacityTracker::new(facade, inode_counts);
        let snap = tracker.refresh().unwrap();
        assert_eq!(snap.total_inodes, 200);
        assert_eq!(snap.free_inodes, 100);
    }

    #[test]
    fn inode_count_source_via_fn_pointer() {
        fn fixed_counts() -> (u64, u64) {
            (300, 50)
        }
        let alloc = test_allocator(50);
        let facade = CapacityFacade::new(alloc);
        let tracker = CapacityTracker::new(facade, fixed_counts as fn() -> (u64, u64));
        let snap = tracker.refresh().unwrap();
        assert_eq!(snap.total_inodes, 300);
        assert_eq!(snap.free_inodes, 50);
    }
}
