//! Per-connection send-concurrency limiter that caps the number of in-flight
//! (sent but unacknowledged) messages per connection, releasing permits on
//! send-completion acknowledgement.
//!
//! This prevents a fast sender from exhausting transport memory when the
//! receiver or network is slow, closing the sender-side concurrency gap
//! between outbound-queue backpressure and receive-window advertisement.
//!
//! ## Architecture
//!
//! ```text
//! Caller
//!   |
//!   +-- try_acquire_send_permit() / acquire_send_permit()
//!        |
//!        +-- check connection state gate
//!        +-- acquire semaphore permit (non-blocking or async)
//!        +-- update high-watermark metric
//!        +-- return SendPermit (releases on drop or explicit release)
//!              |
//!              v
//!         SendPermit is held during send lifecycle
//!              |
//!              +-- Drop (or release()) releases permit back to semaphore
//! ```
//!
//! ## Configuration
//!
//! `max_inflight` defaults to 256 and is configurable per connection via
//! the transport configuration.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};

// ---------------------------------------------------------------------------
// SendConcurrencyError
// ---------------------------------------------------------------------------

/// Errors returned by the send-concurrency limiter.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SendConcurrencyError {
    /// The in-flight limit has been reached; no permit available.
    #[error("send concurrency limit exceeded (max_inflight = {max})")]
    LimitExceeded { max: usize },

    /// The connection is not in a sendable state.
    #[error("connection not in sendable state")]
    ConnectionNotSendable,

    /// The limiter has been shut down (semaphore closed).
    #[error("send concurrency limiter shut down")]
    Shutdown,
}

// ---------------------------------------------------------------------------
// SendConcurrencyLimiter
// ---------------------------------------------------------------------------

/// Per-connection send-concurrency limiter with configurable `max_inflight`.
///
/// Uses a [`tokio::sync::Semaphore`] under the hood. Each acquired permit
/// represents one in-flight send; permits are released when the corresponding
/// send receives its acknowledgement.
///
/// # Metrics
///
/// - `in_flight_current()`: number of currently held permits
/// - `in_flight_high_watermark()`: peak in-flight count observed
/// - `permit_wait_count()`: number of times an async acquire waited
#[derive(Debug)]
pub struct SendConcurrencyLimiter {
    /// The underlying semaphore.
    semaphore: Arc<Semaphore>,
    /// Maximum number of concurrent in-flight sends.
    max_inflight: usize,
    /// Peak in-flight count observed so far.
    in_flight_high_watermark: AtomicU64,
    /// Number of times an async acquire had to wait.
    permit_wait_count: AtomicU64,
}

impl SendConcurrencyLimiter {
    /// Create a new limiter with the given `max_inflight` permit count.
    ///
    /// # Panics
    ///
    /// Panics if `max_inflight` is zero.
    #[must_use]
    pub fn new(max_inflight: usize) -> Self {
        assert!(max_inflight > 0, "max_inflight must be non-zero");
        Self {
            semaphore: Arc::new(Semaphore::new(max_inflight)),
            max_inflight,
            in_flight_high_watermark: AtomicU64::new(0),
            permit_wait_count: AtomicU64::new(0),
        }
    }

    /// Maximum number of concurrent in-flight sends.
    #[must_use]
    pub fn max_inflight(&self) -> usize {
        self.max_inflight
    }

    /// Current number of held permits (in-flight sends).
    #[must_use]
    pub fn in_flight_current(&self) -> usize {
        self.max_inflight - self.semaphore.available_permits()
    }

    /// Peak in-flight count observed.
    #[must_use]
    pub fn in_flight_high_watermark(&self) -> u64 {
        self.in_flight_high_watermark.load(Ordering::Relaxed)
    }

    /// Number of times an async acquire waited for a permit.
    #[must_use]
    pub fn permit_wait_count(&self) -> u64 {
        self.permit_wait_count.load(Ordering::Relaxed)
    }

    /// Try to acquire a send permit without waiting.
    ///
    /// Returns `Ok(SendPermit)` if a permit was acquired, or
    /// `Err(SendConcurrencyError::LimitExceeded)` if the limit is reached.
    pub fn try_acquire(self: &Arc<Self>) -> Result<SendPermit, SendConcurrencyError> {
        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => {
                self.update_high_watermark();
                Ok(SendPermit { _permit: permit })
            }
            Err(TryAcquireError::NoPermits) => Err(SendConcurrencyError::LimitExceeded {
                max: self.max_inflight,
            }),
            Err(TryAcquireError::Closed) => Err(SendConcurrencyError::Shutdown),
        }
    }

    /// Acquire a send permit, waiting asynchronously if none is available.
    ///
    /// Increments the `permit_wait_count` metric.
    pub async fn acquire(self: &Arc<Self>) -> Result<SendPermit, SendConcurrencyError> {
        // Fast path: try non-blocking first.
        match Arc::clone(&self.semaphore).try_acquire_owned() {
            Ok(permit) => {
                self.update_high_watermark();
                return Ok(SendPermit { _permit: permit });
            }
            Err(TryAcquireError::NoPermits) => {
                // Will wait below.
            }
            Err(TryAcquireError::Closed) => return Err(SendConcurrencyError::Shutdown),
        }

        self.permit_wait_count.fetch_add(1, Ordering::Relaxed);

        match Arc::clone(&self.semaphore).acquire_owned().await {
            Ok(permit) => {
                self.update_high_watermark();
                Ok(SendPermit { _permit: permit })
            }
            Err(_closed) => Err(SendConcurrencyError::Shutdown),
        }
    }

    /// Update the high-watermark if the current in-flight count exceeds it.
    fn update_high_watermark(&self) {
        let current = self.in_flight_current() as u64;
        let prev = self.in_flight_high_watermark.load(Ordering::Relaxed);
        if current > prev {
            self.in_flight_high_watermark
                .fetch_max(current, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// SendPermit
// ---------------------------------------------------------------------------

/// A held send-concurrency permit.
///
/// When dropped, the permit is released back to the limiter's semaphore,
/// allowing another send to proceed.  Permits may also be released
/// explicitly via [`release`](Self::release) before drop.
///
/// # Example
///
/// ```ignore
/// let permit = handle.try_acquire_send_permit()?;
/// // ... send message ...
/// drop(permit); // or permit.release();
/// ```
#[derive(Debug)]
pub struct SendPermit {
    _permit: OwnedSemaphorePermit,
}

impl SendPermit {
    /// Explicitly release this permit back to the limiter.
    ///
    /// After calling this, the permit is consumed. Any further use is a
    /// compile error (move).
    pub fn release(self) {
        // OwnedSemaphorePermit::forget() would leak; we just drop it.
        drop(self);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    #[test]
    fn new_creates_limiter_with_capacity() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(256));
        assert_eq!(limiter.max_inflight(), 256);
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[test]
    #[should_panic(expected = "max_inflight must be non-zero")]
    fn new_panics_on_zero_max_inflight() {
        let _ = SendConcurrencyLimiter::new(0);
    }

    #[test]
    fn try_acquire_succeeds_under_limit() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(3));
        let p1 = limiter.try_acquire().unwrap();
        let p2 = limiter.try_acquire().unwrap();
        let p3 = limiter.try_acquire().unwrap();

        assert_eq!(limiter.in_flight_current(), 3);

        // Fourth attempt should fail.
        let result = limiter.try_acquire();
        assert!(matches!(
            result,
            Err(SendConcurrencyError::LimitExceeded { max: 3 })
        ));

        drop(p1);
        assert_eq!(limiter.in_flight_current(), 2);
        drop(p2);
        drop(p3);
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[test]
    fn permit_release_explicit() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(2));
        let p1 = limiter.try_acquire().unwrap();
        let _p2 = limiter.try_acquire().unwrap();

        assert_eq!(limiter.in_flight_current(), 2);
        p1.release();
        assert_eq!(limiter.in_flight_current(), 1);

        // Now we can acquire again.
        let _p3 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_current(), 2);
    }

    #[test]
    fn high_watermark_tracks_peak() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(10));
        assert_eq!(limiter.in_flight_high_watermark(), 0);

        let p1 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_high_watermark(), 1);

        let p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_high_watermark(), 2);

        let p3 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_high_watermark(), 3);

        // Drop one; high-watermark should stay at 3.
        drop(p1);
        assert_eq!(limiter.in_flight_high_watermark(), 3);

        drop(p2);
        drop(p3);
        assert_eq!(limiter.in_flight_current(), 0);
        // High-watermark persists.
        assert_eq!(limiter.in_flight_high_watermark(), 3);
    }

    #[test]
    fn permit_drop_releases() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));
        {
            let _p = limiter.try_acquire().unwrap();
            assert_eq!(limiter.in_flight_current(), 1);
        }
        assert_eq!(limiter.in_flight_current(), 0);

        // Can acquire again.
        let _p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_current(), 1);
    }

    #[test]
    fn zero_max_inflight_edge_case() {
        // max_inflight = 1 means one concurrent send. Zero not allowed.
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));
        let _p = limiter.try_acquire().unwrap();
        let result = limiter.try_acquire();
        assert!(matches!(
            result,
            Err(SendConcurrencyError::LimitExceeded { max: 1 })
        ));
    }

    #[tokio::test]
    async fn acquire_waits_and_succeeds() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));
        let p1 = limiter.try_acquire().unwrap();

        // Spawn a task that releases after a short delay.
        let release_handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(p1);
        });

        // This should wait until p1 is dropped.
        let p2 = limiter.acquire().await.unwrap();
        assert!(limiter.in_flight_current() >= 1);

        drop(p2);
        release_handle.await.unwrap();

        assert_eq!(limiter.in_flight_current(), 0);
        assert_eq!(limiter.permit_wait_count(), 1);
    }

    #[tokio::test]
    async fn concurrent_multi_sender_fairness() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(2));
        let acquired = Arc::new(AtomicUsize::new(0));
        let max_concurrent = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..10 {
            let limiter = Arc::clone(&limiter);
            let acquired = Arc::clone(&acquired);
            let max_concurrent = Arc::clone(&max_concurrent);
            handles.push(tokio::spawn(async move {
                let permit = limiter.acquire().await.unwrap();
                let count = acquired.fetch_add(1, Ordering::SeqCst) + 1;
                let prev_max = max_concurrent.load(Ordering::SeqCst);
                if count > prev_max {
                    max_concurrent.fetch_max(count, Ordering::SeqCst);
                }
                // Hold the permit briefly.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                acquired.fetch_sub(1, Ordering::SeqCst);
                drop(permit);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // At most 2 concurrent senders at any time.
        let peak = max_concurrent.load(Ordering::SeqCst);
        assert!(peak <= 2, "max concurrent {peak} exceeded limit of 2");
    }

    #[tokio::test]
    async fn permit_drop_on_cancel() {
        // Simulate a task being cancelled while holding a permit: the permit
        // is dropped and the semaphore recovers.
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));

        let handle = tokio::spawn({
            let limiter = Arc::clone(&limiter);
            async move {
                let _permit = limiter.acquire().await.unwrap();
                // Never explicitly release — the task will be aborted.
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            }
        });

        // Give the task time to acquire.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(limiter.in_flight_current(), 1);

        // Abort the task; its permit should be dropped.
        handle.abort();
        let _ = handle.await;

        // Permit should now be released.
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(limiter.in_flight_current(), 0);

        // Should be able to acquire again.
        let _p = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_current(), 1);
    }

    #[test]
    fn send_concurrency_error_display() {
        let e = SendConcurrencyError::LimitExceeded { max: 256 };
        assert!(e.to_string().contains("256"));

        let e = SendConcurrencyError::ConnectionNotSendable;
        assert!(e.to_string().contains("not in sendable state"));

        let e = SendConcurrencyError::Shutdown;
        assert!(e.to_string().contains("shut down"));
    }

    #[test]
    fn send_concurrency_error_debug() {
        let e = SendConcurrencyError::LimitExceeded { max: 10 };
        let s = format!("{e:?}");
        assert!(s.contains("LimitExceeded"));
    }

    #[test]
    fn limiter_in_flight_returns_zero_after_all_dropped() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(5));
        let permits: Vec<_> = (0..5).map(|_| limiter.try_acquire().unwrap()).collect();
        assert_eq!(limiter.in_flight_current(), 5);
        drop(permits);
        assert_eq!(limiter.in_flight_current(), 0);
    }

    #[test]
    fn try_acquire_after_full_release_succeeds() {
        let limiter = Arc::new(SendConcurrencyLimiter::new(1));
        let p = limiter.try_acquire().unwrap();
        drop(p);
        let _p2 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.in_flight_current(), 1);
    }

    // -----------------------------------------------------------------------
    // Per-connection isolation tests (#5998)
    // -----------------------------------------------------------------------

    #[test]
    fn per_connection_limiter_isolation_try_acquire() {
        // Two separate limiters (peer A and peer B) must not interfere.
        let peer_a = Arc::new(SendConcurrencyLimiter::new(1));
        let peer_b = Arc::new(SendConcurrencyLimiter::new(1));

        // Saturate peer A.
        let _a = peer_a.try_acquire().unwrap();
        let result = peer_a.try_acquire();
        assert!(matches!(
            result,
            Err(SendConcurrencyError::LimitExceeded { max: 1 })
        ));

        // Peer B should still be able to acquire.
        let _b = peer_b.try_acquire().unwrap();

        // Peer B is now also saturated.
        let result = peer_b.try_acquire();
        assert!(matches!(
            result,
            Err(SendConcurrencyError::LimitExceeded { max: 1 })
        ));

        // Release peer A; peer B should still be saturated.
        drop(_a);
        let _a2 = peer_a.try_acquire().unwrap();
        assert!(matches!(
            peer_b.try_acquire(),
            Err(SendConcurrencyError::LimitExceeded { max: 1 })
        ));
        drop(_a2);
        drop(_b);
    }

    #[tokio::test]
    async fn per_connection_limiter_isolation_async_acquire() {
        let peer_a = Arc::new(SendConcurrencyLimiter::new(1));
        let peer_b = Arc::new(SendConcurrencyLimiter::new(1));

        // Saturate peer A.
        let _a = peer_a.try_acquire().unwrap();

        // Spawn a task that tries to acquire on peer A (will wait).
        let a_handle = {
            let limiter = Arc::clone(&peer_a);
            tokio::spawn(async move {
                let _p = limiter.acquire().await.unwrap();
            })
        };

        // Peer B acquires immediately.
        let _b = peer_b.acquire().await.unwrap();
        assert_eq!(peer_b.in_flight_current(), 1);

        // Release peer A; the waiting task should proceed.
        drop(_a);
        a_handle.await.unwrap();

        // Peer B still has its permit; peer A is now free.
        assert_eq!(peer_b.in_flight_current(), 1);
        assert_eq!(peer_a.in_flight_current(), 0);
        drop(_b);
    }

    #[test]
    fn per_connection_limiter_metrics_independent() {
        let peer_a = Arc::new(SendConcurrencyLimiter::new(5));
        let peer_b = Arc::new(SendConcurrencyLimiter::new(5));

        let _a1 = peer_a.try_acquire().unwrap();
        let _a2 = peer_a.try_acquire().unwrap();
        let _b1 = peer_b.try_acquire().unwrap();

        assert_eq!(peer_a.in_flight_current(), 2);
        assert_eq!(peer_b.in_flight_current(), 1);
        assert_eq!(peer_a.in_flight_high_watermark(), 2);
        assert_eq!(peer_b.in_flight_high_watermark(), 1);

        drop(_a1);
        drop(_a2);
        drop(_b1);
    }
}
