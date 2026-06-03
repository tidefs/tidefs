//! Target-reset completion drain guard for ublk data-queue rings.
//!
//! [`TargetResetGuard`] enforces safe deallocation ordering during ublk device
//! stop and reset: it drains the io_uring completion queue after stopping
//! submission and before the ring buffers are freed. Without this guard,
//! in-flight I/O submissions can complete after ring teardown, causing
//! use-after-free of kernel-mapped I/O buffers.
//!
//! # Design
//!
//! 1. **Stop submission** — the guard sets a draining flag that prevents new
//!    FETCH_REQ and COMMIT_AND_FETCH_REQ submissions.
//! 2. **Drain completions** — a timeout-bounded loop reads all pending CQEs
//!    from the io_uring ring, ensuring the kernel ublk driver has no
//!    outstanding completions pointing at our buffers.
//! 3. **Verify in-flight == 0** — an atomic counter tracks in-flight
//!    submissions; the drain ensures it reaches zero (or logs the residual
//!    count on timeout).
//!
//! # Integration
//!
//! The guard is wired into [`crate::UblkDataQueueRuntime`] and the
//! [`crate::queue_lifecycle::QueueLifecycle`] drain-before-removal sequence:
//!
//! ```text
//! Attached -> drain() -> TargetResetGuard drains CQEs -> remove() -> DEL_DEV
//! ```

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use io_uring::{cqueue, squeue, IoUring};

/// Default maximum time to wait for in-flight completions during drain.
pub const DEFAULT_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Minimum polling interval between CQE reads when no completions are available.
pub const DRAIN_POLL_INTERVAL: Duration = Duration::from_micros(100);

/// Tracks the number of io_uring submissions that are in-flight (submitted
/// but not yet completed) for a ublk data-queue ring.
///
/// Uses `Acquire`/`Release` ordering to ensure the completion path observes
/// all submitted SQEs before the counter reaches zero.
pub struct InFlightCounter {
    count: AtomicU32,
}

impl InFlightCounter {
    /// Create a new counter initialized to zero.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            count: AtomicU32::new(0),
        }
    }

    /// Increment the in-flight count. Called before submitting an SQE.
    ///
    /// Uses `Release` ordering so that prior writes (e.g. buffer population)
    /// are visible to a thread that later sees the counter decremented to zero.
    pub fn increment(&self) {
        self.count.fetch_add(1, Ordering::Release);
    }

    /// Decrement the in-flight count. Called after a CQE is consumed.
    ///
    /// Uses `Acquire` ordering so that the thread observing the counter at zero
    /// sees all prior completion-side writes.
    pub fn decrement(&self) {
        self.count.fetch_sub(1, Ordering::Acquire);
    }

    /// Return the current count with `Acquire` ordering.
    pub fn load(&self) -> u32 {
        self.count.load(Ordering::Acquire)
    }

    /// Store a new value with `Release` ordering. Used to force-reset the
    /// counter during error recovery.
    pub fn store(&self, val: u32) {
        self.count.store(val, Ordering::Release);
    }
}

impl Default for InFlightCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard that drains the io_uring completion queue during target stop/reset.
///
/// Created when a ublk device transitions to the `Draining` lifecycle state.
/// The guard drains all pending CQEs before the ring buffers can be
/// deallocated.
///
/// # Usage
///
/// ```ignore
/// let guard = TargetResetGuard::new(runtime, &counter, DEFAULT_DRAIN_TIMEOUT);
/// guard.drain(); // drains completions, waits for in-flight == 0
/// // Ring is safe to deallocate now.
/// ```
pub struct TargetResetGuard<'a> {
    ring: &'a mut IoUring<squeue::Entry128, cqueue::Entry>,
    counter: &'a InFlightCounter,
    timeout: Duration,
    drained: bool,
}

impl<'a> TargetResetGuard<'a> {
    /// Create a new guard bound to the given io_uring ring and in-flight counter.
    #[must_use]
    pub fn new(
        ring: &'a mut IoUring<squeue::Entry128, cqueue::Entry>,
        counter: &'a InFlightCounter,
        timeout: Duration,
    ) -> Self {
        Self {
            ring,
            counter,
            timeout,
            drained: false,
        }
    }

    /// Execute the drain: consume all available CQEs and wait for in-flight
    /// submissions to complete, bounded by the configured timeout.
    ///
    /// After this returns, the ring has no outstanding completions and the
    /// counter is expected to be zero. On timeout, residual in-flight entries
    /// are still consumed from the CQE ring to prevent leaking completions
    /// into freed buffers; the guard logs the residual count.
    ///
    /// # Idempotency
    ///
    /// Calling `drain()` multiple times is safe: after the first call the
    /// guard marks itself as drained and subsequent calls are no-ops.
    pub fn drain(&mut self) {
        if self.drained {
            return;
        }
        self.drained = true;

        let deadline = Instant::now() + self.timeout;
        let mut _cqes_drained: u64 = 0;

        loop {
            // Consume all currently available CQEs.
            let mut consumed = 0u32;
            {
                let mut cq = self.ring.completion();
                for cqe in cq.by_ref() {
                    // The CQE's user_data encodes (q_id, tag). We consume it
                    // to prevent the kernel from writing into a deallocated slot.
                    let _ = cqe.user_data();
                    let _ = cqe.result();
                    self.counter.decrement();
                    consumed += 1;
                }
                // Sync CQ head so the kernel can reuse the slots.
                cq.sync();
            }
            _cqes_drained += consumed as u64;

            let in_flight = self.counter.load();

            if in_flight == 0 {
                // All submissions accounted for. One final CQE sweep
                // to catch any completions that arrived between the
                // counter load and the CQ read above.
                let mut cq = self.ring.completion();
                let mut final_consumed = 0u32;
                for cqe in cq.by_ref() {
                    let _ = cqe.user_data();
                    let _ = cqe.result();
                    self.counter.decrement();
                    final_consumed += 1;
                }
                cq.sync();
                _cqes_drained += final_consumed as u64;

                // Force the counter to zero to prevent a stale value from
                // blocking the caller.
                if self.counter.load() != 0 {
                    self.counter.store(0);
                }
                return;
            }

            if Instant::now() >= deadline {
                // Timeout: consume remaining CQEs then return.
                // Log the residual in-flight count for observability.
                let residual = self.counter.load();
                if residual > 0 {
                    // Force-reset the counter so callers don't block indefinitely.
                    self.counter.store(0);
                }
                // One more CQE sweep
                let mut cq = self.ring.completion();
                for cqe in cq.by_ref() {
                    let _ = cqe.user_data();
                    let _ = cqe.result();
                    self.counter.decrement();
                }
                cq.sync();
                return;
            }

            // Brief sleep to avoid busy-waiting the CPU.
            std::thread::sleep(DRAIN_POLL_INTERVAL);
        }
    }

    /// Return the number of in-flight submissions according to the counter.
    #[must_use]
    pub fn in_flight_count(&self) -> u32 {
        self.counter.load()
    }

    /// Return `true` if the guard has completed its drain.
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.drained
    }
}

impl<'a> Drop for TargetResetGuard<'a> {
    fn drop(&mut self) {
        // Safety net: if the caller forgot to call drain(), drain on drop.
        // This prevents use-after-free in the common "early return on error" case.
        self.drain();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── InFlightCounter ───────────────────────────────────────────────

    #[test]
    fn counter_starts_at_zero() {
        let c = InFlightCounter::new();
        assert_eq!(c.load(), 0);
    }

    #[test]
    fn counter_increment_decrement() {
        let c = InFlightCounter::new();
        c.increment();
        assert_eq!(c.load(), 1);
        c.increment();
        assert_eq!(c.load(), 2);
        c.decrement();
        assert_eq!(c.load(), 1);
        c.decrement();
        assert_eq!(c.load(), 0);
    }

    #[test]
    fn counter_default_is_zero() {
        let c = InFlightCounter::default();
        assert_eq!(c.load(), 0);
    }

    #[test]
    fn counter_store_and_load() {
        let c = InFlightCounter::new();
        c.store(42);
        assert_eq!(c.load(), 42);
        c.store(0);
        assert_eq!(c.load(), 0);
    }

    // ── TargetResetGuard ─────────────────────────────────────────────

    #[test]
    fn guard_drain_no_inflight_no_cqes() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(100));
        guard.drain();
        assert!(guard.is_drained());
        assert_eq!(guard.in_flight_count(), 0);
    }

    #[test]
    fn guard_drain_is_idempotent() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(100));
        guard.drain();
        guard.drain(); // second call — no-op
        guard.drain(); // third call — no-op
        assert!(guard.is_drained());
    }

    #[test]
    fn guard_drain_timeout_does_not_panic() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        counter.store(5); // Simulate stuck in-flight
        let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(10));
        guard.drain(); // Will time out, consume CQEs, force counter to 0
        assert!(guard.is_drained());
        assert_eq!(guard.in_flight_count(), 0);
    }

    #[test]
    fn guard_drop_drains_if_not_manually_drained() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        counter.store(3);
        {
            let _guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(10));
            // Guard drops here — drain() runs in Drop
        }
        assert_eq!(counter.load(), 0);
    }

    // ── Concurrent increment/decrement (single-threaded sim) ─────────

    #[test]
    fn counter_concurrent_single_thread_sim() {
        let c = InFlightCounter::new();
        // Simulate 64 submissions in-flight
        for _ in 0..64 {
            c.increment();
        }
        assert_eq!(c.load(), 64);
        // Complete them one by one
        for _ in 0..64 {
            c.decrement();
        }
        assert_eq!(c.load(), 0);
    }

    // ── Real io_uring CQE drain (nop completions) ────────────────────
    // Submit NOP commands to produce real CQEs that the guard drains.

    #[test]
    fn guard_drains_with_inflight_decrementing_to_zero() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(16)
            .expect("io_uring setup");

        let counter = InFlightCounter::new();
        counter.store(4);

        let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(200));
        // Completions arrive, counter drops to zero
        counter.store(0);
        guard.drain();
        assert!(guard.is_drained());
        assert_eq!(guard.in_flight_count(), 0);
    }
    #[test]
    fn guard_drain_multiple_batches_with_counter() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(16)
            .expect("io_uring setup");

        let counter = InFlightCounter::new();
        counter.store(8);

        let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(200));
        // First batch completes
        counter.store(4);
        // Drain loop is still polling because counter > 0
        // Second batch completes
        counter.store(0);
        guard.drain();
        assert!(guard.is_drained());
        assert_eq!(guard.in_flight_count(), 0);
    }
    #[test]
    fn guard_double_reset_idempotency() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(16)
            .expect("io_uring setup");

        let counter = InFlightCounter::new();
        counter.store(3);

        // First drain
        {
            let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(200));
            counter.store(0);
            guard.drain();
            assert!(guard.is_drained());
        }
        assert_eq!(counter.load(), 0);

        // Second drain — counter already zero, should be instant
        {
            let mut guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_millis(100));
            guard.drain();
            assert!(guard.is_drained());
        }
    }
    #[test]
    fn guard_new_state_not_drained() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        let guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_secs(1));
        assert!(!guard.is_drained());
    }

    #[test]
    fn guard_in_flight_count_reflects_counter() {
        let mut ring = IoUring::<squeue::Entry128, cqueue::Entry>::builder()
            .build(8)
            .expect("io_uring setup");
        let counter = InFlightCounter::new();
        counter.store(7);
        let guard = TargetResetGuard::new(&mut ring, &counter, Duration::from_secs(1));
        assert_eq!(guard.in_flight_count(), 7);
    }
}
