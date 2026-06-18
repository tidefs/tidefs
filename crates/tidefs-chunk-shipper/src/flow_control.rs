// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Flow-control backpressure for chunk shipping sessions.
//!
//! The [`FlowController`] manages a bounded send window with configurable
//! `max_inflight_chunks`. Before sending each chunk frame the dispatcher
//! must acquire a [`SendPermit`]; when the receiver acknowledges a chunk
//! the permit is released back, opening a slot for the next chunk.
//!
//! This sliding-window model provides natural backpressure: the sender
//! cannot outrun the receiver's ability to process and acknowledge chunks.

/// Errors returned by flow-control operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowControlError {
    /// All send permits are currently held (window exhausted).
    WindowExhausted,
    /// The session is closed and no further permits will be issued.
    SessionClosed,
}

impl std::fmt::Display for FlowControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WindowExhausted => write!(f, "flow-control window exhausted"),
            Self::SessionClosed => write!(f, "flow-control session closed"),
        }
    }
}

impl std::error::Error for FlowControlError {}

/// A send permit granting permission to transmit one chunk.
///
/// Acquired via [`FlowController::try_acquire_send_slot`] and
/// implicitly released via [`FlowController::release_on_ack`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendPermit {
    /// Monotonic sequence number for this permit.
    pub sequence: u64,
}

/// Bounded sliding-window flow controller.
///
/// Limits how many chunks may be in-flight simultaneously. The dispatcher
/// acquires permits before sending; acknowledgements from the receiver
/// release permits back into the pool.
pub struct FlowController {
    /// Maximum number of concurrently in-flight chunks.
    max_inflight: usize,
    /// Number of permits currently held (in-flight).
    inflight_count: usize,
    /// Next monotonic sequence number to assign.
    next_sequence: u64,
    /// Whether the controller has been closed.
    closed: bool,
}

impl FlowController {
    /// Create a new flow controller with `max_inflight` concurrent chunk slots.
    ///
    /// # Panics
    ///
    /// Panics if `max_inflight` is zero.
    #[must_use]
    pub fn new(max_inflight: usize) -> Self {
        assert!(max_inflight > 0, "max_inflight must be at least 1");
        Self {
            max_inflight,
            inflight_count: 0,
            next_sequence: 0,
            closed: false,
        }
    }

    /// Try to acquire a send permit.
    ///
    /// Returns `Ok(SendPermit)` when a slot is available, or
    /// `Err(FlowControlError::WindowExhausted)` when the window is full.
    /// Returns `Err(FlowControlError::SessionClosed)` when the controller
    /// has been closed.
    pub fn try_acquire_send_slot(&mut self) -> Result<SendPermit, FlowControlError> {
        if self.closed {
            return Err(FlowControlError::SessionClosed);
        }
        if self.inflight_count >= self.max_inflight {
            return Err(FlowControlError::WindowExhausted);
        }
        let seq = self.next_sequence;
        self.next_sequence += 1;
        self.inflight_count += 1;
        Ok(SendPermit { sequence: seq })
    }

    /// Release a permit back into the window.
    ///
    /// Called when the receiver acknowledges a chunk. The sequence number
    /// is recorded for bookkeeping but the window is freed unconditionally;
    /// out-of-order acks are tolerated (the window tracks count, not
    /// individual permits).
    pub fn release_on_ack(&mut self, _sequence: u64) {
        if self.inflight_count > 0 {
            self.inflight_count -= 1;
        }
    }

    /// Close the controller. No further permits will be issued.
    pub fn close(&mut self) {
        self.closed = true;
    }

    // ── Accessors ──

    #[must_use]
    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    #[must_use]
    pub fn inflight_count(&self) -> usize {
        self.inflight_count
    }

    #[must_use]
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Whether a new permit can be acquired immediately.
    #[must_use]
    pub fn has_capacity(&self) -> bool {
        !self.closed && self.inflight_count < self.max_inflight
    }
}

// ── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_controller_has_capacity() {
        let fc = FlowController::new(4);
        assert!(fc.has_capacity());
        assert_eq!(fc.inflight_count(), 0);
        assert!(!fc.is_closed());
    }

    #[test]
    fn acquire_reduces_capacity() {
        let mut fc = FlowController::new(2);
        assert!(fc.try_acquire_send_slot().is_ok());
        assert!(fc.has_capacity());
        assert_eq!(fc.inflight_count(), 1);
        assert!(fc.try_acquire_send_slot().is_ok());
        assert!(!fc.has_capacity());
    }

    #[test]
    fn window_exhausted() {
        let mut fc = FlowController::new(1);
        let p = fc.try_acquire_send_slot().unwrap();
        assert_eq!(p.sequence, 0);
        assert_eq!(
            fc.try_acquire_send_slot(),
            Err(FlowControlError::WindowExhausted)
        );
    }

    #[test]
    fn release_opens_slot() {
        let mut fc = FlowController::new(1);
        let p = fc.try_acquire_send_slot().unwrap();
        fc.release_on_ack(p.sequence);
        assert!(fc.has_capacity());
        let p2 = fc.try_acquire_send_slot().unwrap();
        assert_eq!(p2.sequence, 1);
    }

    #[test]
    fn out_of_order_release() {
        let mut fc = FlowController::new(2);
        let _p0 = fc.try_acquire_send_slot().unwrap();
        let p1 = fc.try_acquire_send_slot().unwrap();
        fc.release_on_ack(p1.sequence);
        assert!(fc.has_capacity());
    }

    #[test]
    fn closed_rejects_permits() {
        let mut fc = FlowController::new(4);
        fc.close();
        assert!(fc.is_closed());
        assert_eq!(
            fc.try_acquire_send_slot(),
            Err(FlowControlError::SessionClosed)
        );
    }

    #[test]
    fn release_after_close_still_decrements() {
        let mut fc = FlowController::new(1);
        let p = fc.try_acquire_send_slot().unwrap();
        fc.close();
        fc.release_on_ack(p.sequence);
        assert_eq!(fc.inflight_count(), 0);
    }

    #[test]
    fn monotonic_sequences() {
        let mut fc = FlowController::new(4);
        assert_eq!(fc.try_acquire_send_slot().unwrap().sequence, 0);
        assert_eq!(fc.try_acquire_send_slot().unwrap().sequence, 1);
        assert_eq!(fc.try_acquire_send_slot().unwrap().sequence, 2);
        assert_eq!(fc.next_sequence(), 3);
    }

    #[test]
    #[should_panic(expected = "max_inflight must be at least 1")]
    fn zero_capacity_panics() {
        let _fc = FlowController::new(0);
    }

    #[test]
    fn large_window() {
        let mut fc = FlowController::new(256);
        for i in 0..256 {
            assert_eq!(fc.try_acquire_send_slot().unwrap().sequence, i);
        }
        assert_eq!(
            fc.try_acquire_send_slot(),
            Err(FlowControlError::WindowExhausted)
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            FlowControlError::WindowExhausted.to_string(),
            "flow-control window exhausted"
        );
        assert_eq!(
            FlowControlError::SessionClosed.to_string(),
            "flow-control session closed"
        );
    }
}
