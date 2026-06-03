//! Kernel-mode transaction group sequence counter.
//!
//! `TxgSequenceCounter` provides a monotonic sequence-number allocator for
//! transaction group identifiers in no_std kernel mode. It bridges the
//! [`tidefs_vfs_engine::VfsEngine`] txg lifecycle trait methods (txg_open,
//! txg_commit_prepare, txg_commit_finish) and the committed-root entry
//! persistence path so that higher-level txg submission (#6225) can rely
//! on a concrete primitive for open/commit tracking.
//!
//! # Lifecycle
//!
//! ```text
//! mount/recovery: new(last_committed) or reset(base)
//!       │
//!       ▼
//!   open_txg(base) ──► Ok(txg_id)   (must not already have an open txg)
//!       │
//!       ▼
//!   commit_txg(txg_id) ──► Ok(())    (id must match open txg)
//!       │
//!       ▼
//!   (repeat: open → commit)
//! ```
//!
//! The counter enforces that only one transaction group is open at a time,
//! that commit always refers to the currently-open txg, and that sequence
//! numbers advance monotonically from the last committed or base value.

use core::cmp;

use tidefs_vfs_engine::TxgId;

// ---------------------------------------------------------------------------
// TxgSequenceError
// ---------------------------------------------------------------------------

/// Error returned by [`TxgSequenceCounter`] operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TxgSequenceError {
    /// `commit_txg` was called but no transaction group is open.
    NoOpenTxg,
    /// The `TxgId` passed to `commit_txg` does not match the currently open txg.
    TxgIdMismatch,
    /// `open_txg` was called while a transaction group is already open.
    TxgAlreadyOpen,
}

// ---------------------------------------------------------------------------
// TxgSequenceCounter
// ---------------------------------------------------------------------------

/// Monotonic transaction group sequence counter.
///
/// Tracks the last-committed [`TxgId`] and the currently open txg (if any).
/// All methods are no_std, allocation-free, and use only `core` primitives.
///
/// # Examples
///
/// ```
/// use tidefs_commit_group::txg_sequence::{TxgSequenceCounter, TxgSequenceError};
/// use tidefs_vfs_engine::TxgId;
///
/// let mut counter = TxgSequenceCounter::new(TxgId(0));
/// let txg = counter.open_txg(TxgId(0)).unwrap();
/// assert_eq!(counter.current_txg(), Some(txg));
/// counter.commit_txg(txg).unwrap();
/// assert_eq!(counter.current_txg(), None);
/// ```
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TxgSequenceCounter {
    /// Highest committed `TxgId`.
    last_committed: TxgId,
    /// Currently open txg, if any.
    current_open: Option<TxgId>,
}

impl TxgSequenceCounter {
    /// Create a new counter starting from the given last-committed txg id.
    ///
    /// The counter begins with no open transaction group.
    #[must_use]
    pub const fn new(last_committed: TxgId) -> Self {
        Self {
            last_committed,
            current_open: None,
        }
    }

    /// Open a new transaction group.
    ///
    /// Allocates the next monotonic txg id as `max(last_committed, base) + 1`,
    /// marks it as the current open txg, and returns it.
    ///
    /// # Errors
    ///
    /// Returns [`TxgSequenceError::TxgAlreadyOpen`] if a txg is already open.
    pub fn open_txg(&mut self, base: TxgId) -> Result<TxgId, TxgSequenceError> {
        if self.current_open.is_some() {
            return Err(TxgSequenceError::TxgAlreadyOpen);
        }

        let anchor = cmp::max(self.last_committed, base);
        // Saturating add: wrapping around u64::MAX is practically unreachable
        // but prevents UB in the kernel.
        let next = TxgId(anchor.0.saturating_add(1));

        self.current_open = Some(next);
        Ok(next)
    }

    /// Return the currently open transaction group, if any.
    #[must_use]
    pub const fn current_txg(&self) -> Option<TxgId> {
        self.current_open
    }

    /// Commit the currently open transaction group.
    ///
    /// Validates that `id` matches the currently open txg, advances
    /// `last_committed`, and clears the open slot.
    ///
    /// # Errors
    ///
    /// - [`TxgSequenceError::NoOpenTxg`] if no txg is open.
    /// - [`TxgSequenceError::TxgIdMismatch`] if `id` does not match the open txg.
    pub fn commit_txg(&mut self, id: TxgId) -> Result<(), TxgSequenceError> {
        match self.current_open {
            None => Err(TxgSequenceError::NoOpenTxg),
            Some(open_id) if open_id != id => Err(TxgSequenceError::TxgIdMismatch),
            Some(open_id) => {
                self.last_committed = open_id;
                self.current_open = None;
                Ok(())
            }
        }
    }

    /// Reset the counter to a known base for mount-time recovery.
    ///
    /// Clears any open transaction group and sets the last-committed id to
    /// `base`. Call this during mount/recovery before the first `open_txg`.
    pub fn reset(&mut self, base: TxgId) {
        self.last_committed = base;
        self.current_open = None;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequential_allocation_monotonic() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));

        let txg1 = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg1, TxgId(1));
        counter.commit_txg(txg1).unwrap();

        let txg2 = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg2, TxgId(2));
        counter.commit_txg(txg2).unwrap();

        let txg3 = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg3, TxgId(3));
        counter.commit_txg(txg3).unwrap();
    }

    #[test]
    fn start_from_nonzero_base() {
        let mut counter = TxgSequenceCounter::new(TxgId(100));
        let txg = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg, TxgId(101));
        counter.commit_txg(txg).unwrap();
    }

    #[test]
    fn base_argument_overrides_last_committed() {
        let mut counter = TxgSequenceCounter::new(TxgId(10));
        let txg = counter.open_txg(TxgId(50)).unwrap();
        assert_eq!(txg, TxgId(51));
    }

    #[test]
    fn commit_then_open_cycle() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        for expected in 1..=20u64 {
            let txg = counter.open_txg(TxgId(0)).unwrap();
            assert_eq!(txg, TxgId(expected));
            assert_eq!(counter.current_txg(), Some(txg));
            counter.commit_txg(txg).unwrap();
            assert_eq!(counter.current_txg(), None);
        }
    }

    #[test]
    fn double_open_error() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        counter.open_txg(TxgId(0)).unwrap();
        let err = counter.open_txg(TxgId(0)).unwrap_err();
        assert_eq!(err, TxgSequenceError::TxgAlreadyOpen);
    }

    #[test]
    fn commit_without_open_error() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        let err = counter.commit_txg(TxgId(1)).unwrap_err();
        assert_eq!(err, TxgSequenceError::NoOpenTxg);
    }

    #[test]
    fn commit_id_mismatch_error() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        let txg = counter.open_txg(TxgId(0)).unwrap();
        let err = counter.commit_txg(TxgId(999)).unwrap_err();
        assert_eq!(err, TxgSequenceError::TxgIdMismatch);
        assert_eq!(counter.current_txg(), Some(txg));
    }

    #[test]
    fn commit_consumes_open_slot() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        let txg = counter.open_txg(TxgId(0)).unwrap();
        counter.commit_txg(txg).unwrap();
        assert!(counter.current_txg().is_none());
        let err = counter.commit_txg(txg).unwrap_err();
        assert_eq!(err, TxgSequenceError::NoOpenTxg);
    }

    #[test]
    fn reset_clears_open_and_sets_base() {
        let mut counter = TxgSequenceCounter::new(TxgId(5));
        counter.open_txg(TxgId(0)).unwrap();
        assert!(counter.current_txg().is_some());
        counter.reset(TxgId(42));
        assert_eq!(counter.current_txg(), None);
        let txg = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg, TxgId(43));
    }

    #[test]
    fn reset_preserves_no_open_txg() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        counter.reset(TxgId(7));
        assert!(counter.current_txg().is_none());
        let txg = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg, TxgId(8));
    }

    #[test]
    fn wraparound_boundary_saturates() {
        let mut counter = TxgSequenceCounter::new(TxgId(u64::MAX));
        let txg = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg, TxgId(u64::MAX));
    }

    #[test]
    fn zero_base_first_txg_is_one() {
        let mut counter = TxgSequenceCounter::new(TxgId(0));
        let txg = counter.open_txg(TxgId(0)).unwrap();
        assert_eq!(txg, TxgId(1));
    }

    #[test]
    fn current_txg_returns_none_initially() {
        let counter = TxgSequenceCounter::new(TxgId(100));
        assert_eq!(counter.current_txg(), None);
    }
}
