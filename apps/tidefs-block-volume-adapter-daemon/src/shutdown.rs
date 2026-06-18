// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Block-volume adapter daemon graceful shutdown state machine.
//!
//! [`ShutdownHandle`] provides a signal-driven ordered teardown:
//! 1. Signal receipt sets the atomic shutdown flag.
//! 2. In-flight ublk commands are drained with a configurable deadline.
//! 3. Remaining commands past the deadline are failed with EIO.
//! 4. The ublk device is detached via UBLK_CMD_DEL_DEV.
//! 5. The committed root is flushed for crash-safe restart.
//! 6. Exit code 0 on clean shutdown, non-zero on drain timeout.
//!
//! # State machine
//!
//! ```text
//! Running --signal--> Draining --deadline/empty--> Flushing --> Complete
//!                         |
//!                         +-(timeout)--> HungIoFailed --> Flushing --> Complete
//! ```

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Phases of the ordered shutdown sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownPhase {
    /// Normal I/O serving; no shutdown requested.
    Running,
    /// Shutdown signal received; draining in-flight ublk commands.
    Draining,
    /// Drain deadline expired with hung I/O; remaining commands failed with EIO.
    HungIoFailed,
    /// Flushing the committed root to persistent storage.
    Flushing,
    /// Shutdown complete; resources cleaned up.
    Complete,
}

impl ShutdownPhase {
    /// Return a short label for diagnostics.
    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Draining => "draining",
            Self::HungIoFailed => "hung-io-failed",
            Self::Flushing => "flushing",
            Self::Complete => "complete",
        }
    }
}

/// Outcome of the shutdown sequence.
#[derive(Clone, Debug)]
pub struct ShutdownOutcome {
    /// Whether the shutdown was graceful (no hung I/O).
    pub graceful: bool,
    /// Number of CQEs drained during the drain phase.
    pub drained_cqes: u64,
    /// Number of drain iterations (submit_and_wait calls).
    pub drain_iterations: u64,
    /// Whether the drain deadline expired.
    pub drain_timed_out: bool,
    /// Count of in-flight commands that were failed with EIO after timeout.
    pub hung_io_count: u64,
    /// Whether the final committed-root flush completed.
    pub final_flush_completed: bool,
}

/// Handle for coordinating graceful daemon shutdown.
///
/// Created before the I/O serve loop and shared with the signal-handling
/// thread.  The signal thread calls [`shutdown`] on receipt; the I/O loop
/// polls [`should_continue`] and transitions through the drain/flush phases
/// after the loop exits.
pub struct ShutdownHandle {
    flag: Arc<AtomicBool>,
    phase: ShutdownPhase,
    drain_deadline: Option<Instant>,
    /// Number of CQEs processed during the drain phase.
    drained_cqes: u64,
    /// Number of drain iterations.
    drain_iterations: u64,
    /// Count of commands failed with EIO after deadline expiry.
    hung_io_count: u64,
    /// Duration allowed for draining in-flight I/O after shutdown signal.
    drain_timeout: Duration,
}

impl ShutdownHandle {
    /// Create a new handle in the Running phase.
    ///
    /// `drain_timeout` is the maximum time allowed for in-flight I/O to
    /// complete after the shutdown signal is received.  Commands still
    /// in-flight after this deadline are failed with EIO.
    #[must_use]
    pub fn new(drain_timeout: Duration) -> Self {
        Self {
            flag: Arc::new(AtomicBool::new(false)),
            phase: ShutdownPhase::Running,
            drain_deadline: None,
            drained_cqes: 0,
            drain_timeout,
            drain_iterations: 0,
            hung_io_count: 0,
        }
    }

    /// Return a clone of the underlying atomic flag for sharing with the
    /// signal-handling thread.
    #[must_use]
    pub fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.flag)
    }

    /// Signal that shutdown has been requested.
    ///
    /// Called by the signal-handling thread.  Transitions the phase from
    /// Running to Draining and records the drain deadline.
    pub fn request_shutdown(&mut self, drain_deadline: Instant) {
        self.flag.store(true, Ordering::Relaxed);
        self.phase = ShutdownPhase::Draining;
        self.drain_deadline = Some(drain_deadline);
    }

    /// Returns `true` if the I/O serve loop should continue processing.
    ///
    /// The I/O loop calls this at the top of each iteration.  Once it
    /// returns `false`, the loop exits and the caller should begin the
    /// drain sequence.
    #[must_use]
    pub fn should_continue(&self) -> bool {
        !self.flag.load(Ordering::Relaxed)
    }

    /// Returns `true` if shutdown has been requested.
    #[must_use]
    pub fn is_shutdown(&self) -> bool {
        self.flag.load(Ordering::Relaxed)
    }

    /// Current phase of the shutdown sequence.
    #[must_use]
    pub fn phase(&self) -> ShutdownPhase {
        self.phase
    }

    /// Begin the drain phase.
    ///
    /// Must be called once after the I/O loop exits due to shutdown.
    /// Sets the drain deadline if not already set.
    pub fn begin_drain(&mut self, drain_timeout: Duration) {
        self.phase = ShutdownPhase::Draining;
        if self.drain_deadline.is_none() {
            self.drain_deadline = Some(Instant::now() + drain_timeout);
        }
    }

    /// Returns `true` if the drain deadline has expired.
    #[must_use]
    pub fn drain_expired(&self) -> bool {
        self.drain_deadline
            .map(|dl| Instant::now() >= dl)
            .unwrap_or(false)
    }

    /// Returns `true` if the drain phase is still active (deadline not
    /// expired).
    #[must_use]
    pub fn drain_active(&self) -> bool {
        self.phase == ShutdownPhase::Draining && !self.drain_expired()
    }

    /// Record one CQE drained (either completed successfully or failed).
    pub fn record_drain_cqe(&mut self) {
        self.drained_cqes += 1;
    }

    /// Record one drain iteration (submit_and_wait call).
    pub fn record_drain_iteration(&mut self) {
        self.drain_iterations += 1;
    }

    /// Transition the drain phase to HungIoFailed when the deadline expires
    /// with remaining in-flight commands.
    pub fn fail_hung_io(&mut self, count: u64) {
        self.phase = ShutdownPhase::HungIoFailed;
        self.hung_io_count = count;
    }

    /// Transition from draining to the flushing phase.
    pub fn begin_flush(&mut self) {
        self.phase = ShutdownPhase::Flushing;
    }

    /// Mark the shutdown as complete.
    pub fn complete(&mut self) {
        self.phase = ShutdownPhase::Complete;
    }

    /// Build the final outcome report.
    #[must_use]
    pub fn outcome(&self) -> ShutdownOutcome {
        ShutdownOutcome {
            graceful: self.hung_io_count == 0,
            drained_cqes: self.drained_cqes,
            drain_iterations: self.drain_iterations,
            drain_timed_out: self.hung_io_count > 0,
            hung_io_count: self.hung_io_count,
            final_flush_completed: self.phase == ShutdownPhase::Complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Initial state ───────────────────────────────────────────────

    #[test]
    fn new_handle_starts_running() {
        let handle = ShutdownHandle::new(Duration::from_secs(30));
        assert_eq!(handle.phase(), ShutdownPhase::Running);
        assert!(handle.should_continue());
        assert!(!handle.is_shutdown());
        assert!(!handle.drain_expired());
    }

    #[test]
    fn flag_is_shared_and_independent() {
        let handle = ShutdownHandle::new(Duration::from_secs(5));
        let flag = handle.flag();
        assert!(!flag.load(Ordering::Relaxed));
        flag.store(true, Ordering::Relaxed);
        assert!(handle.is_shutdown());
        assert!(!handle.should_continue());
    }

    // ── Transition: Running → Draining ──────────────────────────────

    #[test]
    fn request_shutdown_transitions_to_draining() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        let deadline = Instant::now() + Duration::from_secs(5);
        handle.request_shutdown(deadline);
        assert_eq!(handle.phase(), ShutdownPhase::Draining);
        assert!(handle.is_shutdown());
        assert!(!handle.should_continue());
    }

    #[test]
    fn drain_deadline_set_after_shutdown_request() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        let deadline = Instant::now() + Duration::from_secs(5);
        handle.request_shutdown(deadline);
        assert!(!handle.drain_expired()); // deadline is in the future
        assert!(handle.drain_active());
    }

    #[test]
    fn drain_deadline_expires() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        let deadline = Instant::now() - Duration::from_secs(1); // in the past
        handle.request_shutdown(deadline);
        assert!(handle.drain_expired());
        assert!(!handle.drain_active());
    }

    // ── begin_drain ─────────────────────────────────────────────────

    #[test]
    fn begin_drain_sets_phase_and_deadline() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        // Simulate signal received externally
        handle.flag.store(true, Ordering::Relaxed);
        assert_eq!(handle.phase(), ShutdownPhase::Running);

        handle.begin_drain(Duration::from_secs(5));
        assert_eq!(handle.phase(), ShutdownPhase::Draining);
        assert!(!handle.drain_expired());
    }

    #[test]
    fn begin_drain_preserves_existing_deadline() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        let original = Instant::now() + Duration::from_secs(60);
        handle.request_shutdown(original);
        // begin_drain should not overwrite the existing deadline
        handle.begin_drain(Duration::from_secs(1));
        assert!(!handle.drain_expired()); // original is 60s away
    }

    // ── Drain counters ──────────────────────────────────────────────

    #[test]
    fn drain_cqe_counter() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        handle.record_drain_cqe();
        handle.record_drain_cqe();
        handle.record_drain_cqe();
        assert_eq!(handle.outcome().drained_cqes, 3);
    }

    #[test]
    fn drain_iteration_counter() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        handle.record_drain_iteration();
        handle.record_drain_iteration();
        assert_eq!(handle.outcome().drain_iterations, 2);
    }

    // ── Hung I/O failure ────────────────────────────────────────────

    #[test]
    fn fail_hung_io_transitions_to_hung_io_failed() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        handle.flag.store(true, Ordering::Relaxed);
        handle.begin_drain(Duration::from_secs(0)); // immediate expiry
        handle.fail_hung_io(5);
        assert_eq!(handle.phase(), ShutdownPhase::HungIoFailed);
        assert_eq!(handle.hung_io_count, 5);
    }

    #[test]
    fn outcome_reports_hung_io() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(10));
        handle.flag.store(true, Ordering::Relaxed);
        handle.begin_drain(Duration::from_secs(0));
        handle.fail_hung_io(3);
        let outcome = handle.outcome();
        assert!(!outcome.graceful);
        assert!(outcome.drain_timed_out);
        assert_eq!(outcome.hung_io_count, 3);
    }

    // ── Full sequence: signal → drain → flush → complete ────────────

    #[test]
    fn full_graceful_shutdown_sequence() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(30));
        assert_eq!(handle.phase(), ShutdownPhase::Running);

        // Signal received
        handle.request_shutdown(Instant::now() + Duration::from_secs(30));
        assert_eq!(handle.phase(), ShutdownPhase::Draining);

        // Drain completes (no hung I/O)
        handle.record_drain_cqe();
        handle.record_drain_iteration();

        // Flush
        handle.begin_flush();
        assert_eq!(handle.phase(), ShutdownPhase::Flushing);

        // Complete
        handle.complete();
        assert_eq!(handle.phase(), ShutdownPhase::Complete);

        let outcome = handle.outcome();
        assert!(outcome.graceful);
        assert!(!outcome.drain_timed_out);
        assert_eq!(outcome.hung_io_count, 0);
        assert!(outcome.final_flush_completed);
        assert_eq!(outcome.drained_cqes, 1);
        assert_eq!(outcome.drain_iterations, 1);
    }

    #[test]
    fn shutdown_with_hung_io_sequence() {
        let mut handle = ShutdownHandle::new(Duration::from_secs(30));
        handle.request_shutdown(Instant::now() - Duration::from_secs(1)); // expired
        handle.fail_hung_io(2);
        handle.begin_flush();
        handle.complete();

        let outcome = handle.outcome();
        assert!(!outcome.graceful);
        assert!(outcome.drain_timed_out);
        assert_eq!(outcome.hung_io_count, 2);
        assert!(outcome.final_flush_completed);
    }

    // ── Phase labels ────────────────────────────────────────────────

    #[test]
    fn phase_labels_are_distinct() {
        let labels: Vec<&str> = [
            ShutdownPhase::Running,
            ShutdownPhase::Draining,
            ShutdownPhase::HungIoFailed,
            ShutdownPhase::Flushing,
            ShutdownPhase::Complete,
        ]
        .iter()
        .map(|p| p.label())
        .collect();

        // All labels are distinct
        let unique: std::collections::HashSet<_> = labels.iter().collect();
        assert_eq!(unique.len(), labels.len());

        // Verify specific labels
        assert_eq!(ShutdownPhase::Running.label(), "running");
        assert_eq!(ShutdownPhase::Draining.label(), "draining");
        assert_eq!(ShutdownPhase::HungIoFailed.label(), "hung-io-failed");
        assert_eq!(ShutdownPhase::Flushing.label(), "flushing");
        assert_eq!(ShutdownPhase::Complete.label(), "complete");
    }
}
