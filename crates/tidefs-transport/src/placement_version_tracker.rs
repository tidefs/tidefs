//! Placement version tracker: bridges placement map versions from
//! PlacementDispatch into the membership and multi-node workflow.
//!
//! [`PlacementVersionTracker`] is a small state cell that the storage-node
//! service uses to publish the current placement map version into the
//! membership view. Membership views carry the placement version so that
//! every node in the cluster observes one consistent map version.
//!
//! # Usage
//!
//! 1. The node that owns the [`PlacementDispatch`] calls
//!    [`PlacementVersionTracker::update`] after `set_placement_map()`.
//! 2. Before broadcasting a [`MembershipView`], the node calls
//!    [`PlacementVersionTracker::current_version`] and sets the
//!    `placement_version` field on the view.
//! 3. Receiving nodes compare the view's `placement_version` against
//!    their own placement version. A mismatch signals that a rebalance
//!    is in progress or the node is stale.
//!
//! # Thread safety
//!
//! The tracker uses an `AtomicU64` for the version so it can be read
//! from any thread without locking.

use std::sync::atomic::{AtomicU64, Ordering};

/// Monotonic placement version tracker.
///
/// When the placement map changes (version increments), the node that
/// owns the map updates this tracker. The current version is then
/// embedded in membership views so all cluster nodes observe the
/// same version.
#[derive(Debug, Default)]
pub struct PlacementVersionTracker {
    /// Current placement map version (0 = none).
    version: AtomicU64,
}

impl PlacementVersionTracker {
    /// Create a new tracker, initially with version 0 (no placement yet).
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: AtomicU64::new(0),
        }
    }

    /// Create a tracker initialized to a specific version.
    #[must_use]
    pub fn with_version(version: u64) -> Self {
        Self {
            version: AtomicU64::new(version),
        }
    }

    /// Return the current placement version (0 = no placement yet).
    #[must_use]
    pub fn current_version(&self) -> u64 {
        self.version.load(Ordering::Acquire)
    }

    /// Update the tracked version. Must be monotonic (newer >= current).
    ///
    /// # Panics
    ///
    /// Panics if `version` is less than the current tracked version,
    /// ensuring monotonic progression.
    pub fn update(&self, version: u64) {
        let prev = self.version.swap(version, Ordering::Release);
        assert!(
            version >= prev,
            "version must be monotonic: {version} < {prev}"
        );
    }

    /// Try to update the version; returns the previous version on success,
    /// or an error on non-monotonic update.
    pub fn try_update(&self, version: u64) -> Result<u64, u64> {
        let prev = self.version.load(Ordering::Acquire);
        if version < prev {
            return Err(prev);
        }
        self.version.store(version, Ordering::Release);
        Ok(prev)
    }

    /// Whether a placement map has been set (version > 0).
    #[must_use]
    pub fn has_placement(&self) -> bool {
        self.current_version() > 0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_tracker_starts_at_zero() {
        let t = PlacementVersionTracker::new();
        assert_eq!(t.current_version(), 0);
        assert!(!t.has_placement());
    }

    #[test]
    fn with_version_initializes_correctly() {
        let t = PlacementVersionTracker::with_version(5);
        assert_eq!(t.current_version(), 5);
        assert!(t.has_placement());
    }

    #[test]
    fn update_increments_version() {
        let t = PlacementVersionTracker::new();
        t.update(1);
        assert_eq!(t.current_version(), 1);
        t.update(3);
        assert_eq!(t.current_version(), 3);
    }

    #[test]
    fn update_same_version_is_allowed() {
        let t = PlacementVersionTracker::with_version(7);
        t.update(7); // same version is ok (idempotent)
        assert_eq!(t.current_version(), 7);
    }

    #[test]
    #[should_panic(expected = "version must be monotonic")]
    fn update_rejects_older_version() {
        let t = PlacementVersionTracker::with_version(10);
        t.update(5);
    }

    #[test]
    fn try_update_rejects_older_version() {
        let t = PlacementVersionTracker::with_version(10);
        assert_eq!(t.try_update(5), Err(10));
        assert_eq!(t.current_version(), 10); // unchanged
    }

    #[test]
    fn try_update_returns_previous() {
        let t = PlacementVersionTracker::with_version(3);
        assert_eq!(t.try_update(5), Ok(3));
        assert_eq!(t.current_version(), 5);
    }

    #[test]
    fn has_placement_reflects_state() {
        let t = PlacementVersionTracker::new();
        assert!(!t.has_placement());
        t.update(1);
        assert!(t.has_placement());
    }
}
