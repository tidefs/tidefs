//! Per-connection epoch gate for rejecting stale-epoch inbound messages.
//!
//! [`EpochGate`] holds a monotonically increasing `current_epoch` and rejects
//! inbound messages whose epoch is behind the gate. This enforces the invariant
//! that after a membership epoch transition, messages from peers still operating
//! on a prior epoch are not processed against the new epoch state.
//!
//! # Relationship to EpochBarrier
//!
//! [`crate::epoch_barrier::EpochBarrier`] wraps outbound messages with a
//! full epoch-stamped wire format (magic, epoch, seq, plen, digest), enforces
//! epoch ordering on receive, and queues future-epoch messages. `EpochGate`
//! complements this by providing a lightweight, per-connection gate that
//! operates on the framing header epoch field without the full wire-format
//! overhead. The two are independent: `EpochBarrier` provides fine-grained
//! epoch fencing per message, while `EpochGate` provides connection-level
//! epoch admission.
//!
//! # Integration point
//!
//! `EpochGate` is attached to [`crate::receive_loop::ConnectionReceiver`]
//! and checked in `dispatch_frames` after extracting the epoch from the
//! envelope header. The membership subscriber bridge calls `set_epoch`
//! on epoch-commit events.

use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// EpochGate
// ---------------------------------------------------------------------------

/// Transport-layer epoch gate that rejects inbound messages carrying a stale
/// epoch identifier.
///
/// # Thread safety
///
/// `EpochGate` uses `AtomicU64` for the current epoch and rejection counter,
/// making it safe to share across threads without external synchronization.
/// `set_epoch` panics on non-monotonic updates (protocol invariant).
pub struct EpochGate {
    /// Current membership epoch. Messages with epoch < this value are rejected.
    current_epoch: AtomicU64,
    /// Total count of stale-epoch messages rejected by this gate.
    pub stale_epoch_rejected: AtomicU64,
}

impl EpochGate {
    /// Create a new epoch gate starting at the given epoch.
    #[must_use]
    pub fn new(initial_epoch: u64) -> Self {
        Self {
            current_epoch: AtomicU64::new(initial_epoch),
            stale_epoch_rejected: AtomicU64::new(0),
        }
    }

    /// Create a new epoch gate starting at epoch 0.
    #[must_use]
    pub fn at_zero() -> Self {
        Self::new(0)
    }

    /// Return the current barrier epoch.
    #[must_use]
    pub fn current_epoch(&self) -> u64 {
        self.current_epoch.load(Ordering::Acquire)
    }

    /// Advance the gate to a new epoch.
    ///
    /// # Panics
    ///
    /// Panics if `new_epoch <= self.current_epoch()` (non-monotonic update).
    /// The membership epoch must always advance; regression indicates a
    /// protocol bug.
    pub fn set_epoch(&self, new_epoch: u64) {
        let prev = self.current_epoch.load(Ordering::Acquire);
        assert!(
            new_epoch > prev,
            "epoch must advance: {new_epoch} <= {prev}"
        );
        self.current_epoch.store(new_epoch, Ordering::Release);
    }

    /// Check whether a message with the given epoch should be accepted.
    ///
    /// Returns `Ok(())` if `message_epoch >= current_epoch` (current or
    /// future-epoch messages are accepted -- future-epoch queuing is the
    /// responsibility of [`crate::epoch_barrier::EpochBarrier`]).
    ///
    /// Returns `Err(EpochRejected)` if `message_epoch < current_epoch`
    /// (stale message). The rejection counter is incremented atomically.
    pub fn check(&self, message_epoch: u64) -> Result<(), EpochRejected> {
        let current = self.current_epoch.load(Ordering::Acquire);
        if message_epoch < current {
            self.stale_epoch_rejected.fetch_add(1, Ordering::Relaxed);
            return Err(EpochRejected {
                current_epoch: current,
                received_epoch: message_epoch,
            });
        }
        Ok(())
    }

    /// Return the total number of stale-epoch messages rejected.
    #[must_use]
    pub fn rejected_count(&self) -> u64 {
        self.stale_epoch_rejected.load(Ordering::Relaxed)
    }
}

impl Default for EpochGate {
    fn default() -> Self {
        Self::at_zero()
    }
}

// ---------------------------------------------------------------------------
// EpochRejected
// ---------------------------------------------------------------------------

/// Error returned when a message is rejected for carrying a stale epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRejected {
    /// The current gate epoch.
    pub current_epoch: u64,
    /// The epoch carried by the rejected message.
    pub received_epoch: u64,
}

impl core::fmt::Display for EpochRejected {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "stale epoch: message epoch {} < gate epoch {}",
            self.received_epoch, self.current_epoch
        )
    }
}

impl std::error::Error for EpochRejected {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_starts_at_specified_epoch() {
        let gate = EpochGate::new(5);
        assert_eq!(gate.current_epoch(), 5);
    }

    #[test]
    fn gate_accepts_current_epoch() {
        let gate = EpochGate::new(3);
        assert!(gate.check(3).is_ok());
    }

    #[test]
    fn gate_accepts_future_epoch() {
        let gate = EpochGate::new(3);
        assert!(gate.check(10).is_ok());
    }

    #[test]
    fn gate_rejects_stale_epoch() {
        let gate = EpochGate::new(5);
        let err = gate.check(4).unwrap_err();
        assert_eq!(err.current_epoch, 5);
        assert_eq!(err.received_epoch, 4);
        assert_eq!(gate.rejected_count(), 1);
    }

    #[test]
    fn gate_rejects_epoch_zero_when_at_one() {
        let gate = EpochGate::new(1);
        assert!(gate.check(0).is_err());
        assert_eq!(gate.rejected_count(), 1);
    }

    #[test]
    fn gate_accepts_at_epoch_zero() {
        let gate = EpochGate::new(0);
        assert!(gate.check(0).is_ok());
        assert_eq!(gate.rejected_count(), 0);
    }

    #[test]
    fn set_epoch_panics_on_non_monotonic_update() {
        let gate = EpochGate::new(5);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.set_epoch(3);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn set_epoch_panics_on_equal_update() {
        let gate = EpochGate::new(5);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            gate.set_epoch(5);
        }));
        assert!(result.is_err());
    }

    #[test]
    fn set_epoch_succeeds_on_forward_update() {
        let gate = EpochGate::new(5);
        gate.set_epoch(10);
        assert_eq!(gate.current_epoch(), 10);
    }

    #[test]
    fn rejection_counter_increments_per_rejection() {
        let gate = EpochGate::new(2);
        assert!(gate.check(0).is_err());
        assert!(gate.check(1).is_err());
        assert!(gate.check(0).is_err());
        assert_eq!(gate.rejected_count(), 3);
    }

    #[test]
    fn acceptance_does_not_increment_rejection_counter() {
        let gate = EpochGate::new(3);
        assert!(gate.check(3).is_ok());
        assert!(gate.check(5).is_ok());
        assert_eq!(gate.rejected_count(), 0);
    }

    #[test]
    fn concurrent_readers_see_consistent_epoch() {
        let gate = std::sync::Arc::new(EpochGate::new(1));
        let g2 = gate.clone();
        let h = std::thread::spawn(move || {
            g2.set_epoch(5);
        });
        h.join().unwrap();
        assert_eq!(gate.current_epoch(), 5);
    }

    #[test]
    fn epoch_rejected_display_format() {
        let err = EpochRejected {
            current_epoch: 5,
            received_epoch: 3,
        };
        let s = format!("{err}");
        assert!(s.contains("stale epoch"));
        assert!(s.contains("3"));
        assert!(s.contains("5"));
    }

    #[test]
    fn default_is_epoch_zero() {
        let gate = EpochGate::default();
        assert_eq!(gate.current_epoch(), 0);
    }
}
