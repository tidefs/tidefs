//! Block device open/release lifecycle with exclusive-open guard.
//!
//! This module implements the `block_device_operations::open` and `release`
//! entrypoints for the block-kmod crate. It enforces FMODE_EXCL semantics,
//! reference-counts open handles, and triggers backend initialization on
//! first-open and teardown on last-close.
//!
//! # FMODE_EXCL contract
//!
//! - A non-exclusive open succeeds as long as no exclusive holder currently
//!   owns the device.
//! - An exclusive open (FMODE_EXCL) succeeds only when the device has zero
//!   active open handles.
//! - Once exclusively held, all further open requests — exclusive or
//!   non-exclusive — are rejected with EBUSY until the exclusive holder
//!   releases.
//!
//! # Backend lifecycle integration
//!
//! The [`BlockLifecycle`] trait provides init/teardown hooks that the
//! device calls on first-open and last-close respectively. Backends
//! that don't need per-open/close resource management can use the
//! default no-op implementations.

use core::fmt;

#[cfg(CONFIG_RUST)]
use crate::tidefs_kmod_bridge::BridgeResult;
#[cfg(not(CONFIG_RUST))]
use tidefs_kmod_bridge::BridgeResult;

// ── BlockLifecycle ──────────────────────────────────────────────────────

/// Extension trait for storage backends that require initialization on
/// first open and teardown on last close.
///
/// Default implementations are no-ops, so backends that don't need
/// special per-handle lifecycle management can derive this trait
/// without custom logic.
pub trait BlockLifecycle {
    /// Called on first open.
    ///
    /// May allocate resources, validate backing storage integrity, or
    /// perform any one-time setup needed before I/O dispatch.
    ///
    /// # Errors
    ///
    /// Returns an error if initialization fails, which causes the
    /// open to be refused.
    fn init(&mut self) -> BridgeResult<()> {
        Ok(())
    }

    /// Called on last close.
    ///
    /// Should flush pending writes, release resources, and prepare the
    /// backend for potential re-initialization on a subsequent first open.
    ///
    /// # Errors
    ///
    /// Returns an error if teardown fails; the device remains in the
    /// released state regardless.
    fn teardown(&mut self) -> BridgeResult<()> {
        Ok(())
    }
}

// ── OpenError ───────────────────────────────────────────────────────────

/// Error returned when an open request cannot be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenError {
    /// The device is already held exclusively; a second FMODE_EXCL
    /// or non-exclusive open was attempted.
    ExclusiveConflict,
    /// The device has existing non-exclusive openers; an exclusive
    /// open conflicts with them.
    BusyWithOtherOpeners,
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExclusiveConflict => {
                write!(f, "device is already held exclusively")
            }
            Self::BusyWithOtherOpeners => {
                write!(f, "device has existing open handles")
            }
        }
    }
}

// ── ReleaseOutcome ─────────────────────────────────────────────────────

/// Outcome of a release operation, indicating whether this was the
/// last close (triggering backend teardown).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// Not the last close; `open_count` remaining handles are still active.
    StillOpen { open_count: u32 },
    /// Last close; the backend should be torn down.
    LastClose,
}

// ── BlockOpenGuard ──────────────────────────────────────────────────────

/// Guards block device open/release lifecycle with FMODE_EXCL enforcement
/// and reference counting.
///
/// Used by [`TidefsBlockDevice`](crate::device::TidefsBlockDevice) to
/// coordinate the kernel `block_device_operations::open` and `release`
/// entrypoints.
///
/// # Thread safety
///
/// `BlockOpenGuard` is not internally synchronized. The caller
/// (typically the block-device operation handlers) is responsible
/// for serializing open/release calls. In the Linux kernel, the
/// block layer already serializes `open` and `release` per gendisk.
pub struct BlockOpenGuard {
    /// Whether a caller currently holds FMODE_EXCL.
    exclusive_held: bool,
    /// Number of active open handles (exclusive hold counts as 1).
    open_count: u32,
}

impl Default for BlockOpenGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockOpenGuard {
    /// Create a new guard in the fully-released state (no open handles).
    #[must_use]
    pub const fn new() -> Self {
        Self {
            exclusive_held: false,
            open_count: 0,
        }
    }

    /// Record an open request.
    ///
    /// * `exclusive` — whether FMODE_EXCL semantics are requested.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::ExclusiveConflict`] if the device is already
    /// held exclusively. Returns [`OpenError::BusyWithOtherOpeners`] if
    /// an exclusive open is attempted while non-exclusive handles are open.
    pub fn open(&mut self, exclusive: bool) -> Result<(), OpenError> {
        if self.exclusive_held {
            return Err(OpenError::ExclusiveConflict);
        }
        if exclusive {
            if self.open_count > 0 {
                return Err(OpenError::BusyWithOtherOpeners);
            }
            self.exclusive_held = true;
        }
        self.open_count += 1;
        Ok(())
    }

    /// Record a release (close) request.
    ///
    /// Returns [`ReleaseOutcome::LastClose`] when the open count drops
    /// to zero, signalling that backend teardown should occur.
    #[must_use]
    pub fn release(&mut self) -> ReleaseOutcome {
        if self.open_count > 0 {
            self.open_count -= 1;
        }
        if self.open_count == 0 {
            self.exclusive_held = false;
            ReleaseOutcome::LastClose
        } else {
            ReleaseOutcome::StillOpen {
                open_count: self.open_count,
            }
        }
    }

    /// Current number of open handles.
    #[must_use]
    pub fn open_count(&self) -> u32 {
        self.open_count
    }

    /// Whether the device is currently held exclusively.
    #[must_use]
    pub fn is_exclusive_held(&self) -> bool {
        self.exclusive_held
    }
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── open: non-exclusive ─────────────────────────────────────────────

    #[test]
    fn open_non_exclusive_succeeds() {
        let mut guard = BlockOpenGuard::new();
        assert!(guard.open(false).is_ok());
        assert_eq!(guard.open_count(), 1);
        assert!(!guard.is_exclusive_held());
    }

    #[test]
    fn multiple_non_exclusive_opens_succeed() {
        let mut guard = BlockOpenGuard::new();
        for i in 0..5 {
            assert!(guard.open(false).is_ok(), "open {i} failed");
        }
        assert_eq!(guard.open_count(), 5);
        assert!(!guard.is_exclusive_held());
    }

    // ── open: exclusive ─────────────────────────────────────────────────

    #[test]
    fn open_exclusive_succeeds() {
        let mut guard = BlockOpenGuard::new();
        assert!(guard.open(true).is_ok());
        assert_eq!(guard.open_count(), 1);
        assert!(guard.is_exclusive_held());
    }

    #[test]
    fn open_second_exclusive_rejected() {
        let mut guard = BlockOpenGuard::new();
        guard.open(true).unwrap();
        assert_eq!(guard.open(true), Err(OpenError::ExclusiveConflict));
        assert_eq!(guard.open_count(), 1);
        assert!(guard.is_exclusive_held());
    }

    #[test]
    fn open_exclusive_after_non_exclusive_rejected() {
        let mut guard = BlockOpenGuard::new();
        guard.open(false).unwrap();
        assert_eq!(guard.open(true), Err(OpenError::BusyWithOtherOpeners));
        assert_eq!(guard.open_count(), 1);
        assert!(!guard.is_exclusive_held());
    }

    #[test]
    fn open_non_exclusive_after_exclusive_rejected() {
        let mut guard = BlockOpenGuard::new();
        guard.open(true).unwrap();
        assert_eq!(guard.open(false), Err(OpenError::ExclusiveConflict));
        assert_eq!(guard.open_count(), 1);
        assert!(guard.is_exclusive_held());
    }

    // ── release ─────────────────────────────────────────────────────────

    #[test]
    fn release_non_last_returns_still_open() {
        let mut guard = BlockOpenGuard::new();
        guard.open(false).unwrap();
        guard.open(false).unwrap();
        assert_eq!(guard.release(), ReleaseOutcome::StillOpen { open_count: 1 });
        assert_eq!(guard.open_count(), 1);
    }

    #[test]
    fn release_last_close_clears_exclusive() {
        let mut guard = BlockOpenGuard::new();
        guard.open(true).unwrap();
        assert_eq!(guard.release(), ReleaseOutcome::LastClose);
        assert_eq!(guard.open_count(), 0);
        assert!(!guard.is_exclusive_held());
    }

    #[test]
    fn release_last_close_after_multiple_non_exclusive_opens() {
        let mut guard = BlockOpenGuard::new();
        guard.open(false).unwrap();
        guard.open(false).unwrap();
        guard.open(false).unwrap();
        let _ = guard.release();
        let _ = guard.release();
        assert_eq!(guard.release(), ReleaseOutcome::LastClose);
        assert_eq!(guard.open_count(), 0);
    }

    #[test]
    fn release_from_empty_guard_returns_last_close() {
        let mut guard = BlockOpenGuard::new();
        // Releasing an already-empty guard underflow-guards and returns
        // LastClose; open_count stays at 0.
        assert_eq!(guard.release(), ReleaseOutcome::LastClose);
        assert_eq!(guard.open_count(), 0);
    }

    // ── re-open after last close ────────────────────────────────────────

    #[test]
    fn open_after_last_close_succeeds() {
        let mut guard = BlockOpenGuard::new();
        guard.open(true).unwrap();
        let _ = guard.release();
        assert!(guard.open(false).is_ok());
        assert_eq!(guard.open_count(), 1);
        assert!(!guard.is_exclusive_held());
    }

    #[test]
    fn open_exclusive_after_full_cycle_succeeds() {
        let mut guard = BlockOpenGuard::new();
        // cycle 1: exclusive
        guard.open(true).unwrap();
        let _ = guard.release();
        // cycle 2: non-exclusive
        guard.open(false).unwrap();
        let _ = guard.release();
        // cycle 3: exclusive again
        assert!(guard.open(true).is_ok());
        assert!(guard.is_exclusive_held());
    }

    // ── interleaved ─────────────────────────────────────────────────────

    #[test]
    fn interleaved_open_release_maintains_counts() {
        let mut guard = BlockOpenGuard::new();
        guard.open(false).unwrap(); // 1
        guard.open(false).unwrap(); // 2
        let _ = guard.release(); // 1
        guard.open(false).unwrap(); // 2
        let _ = guard.release(); // 1
        let _ = guard.release(); // 0 — last close
        assert_eq!(guard.open_count(), 0);
    }

    #[test]
    fn exclusive_open_during_active_non_exclusive_fails() {
        let mut guard = BlockOpenGuard::new();
        guard.open(false).unwrap();
        guard.open(false).unwrap();
        let _ = guard.release(); // 1 remaining
        assert_eq!(guard.open(true), Err(OpenError::BusyWithOtherOpeners));
    }
}
