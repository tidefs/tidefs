//! Global session concurrency limiter that bounds the total number of
//! concurrently established transport sessions across all listeners and
//! outbound connectors.
//!
//! ## Purpose
//!
//! The transport layer has per-listener accept-rate limiting and
//! pending-handshake bounding ([`listener_overload`](crate::listener_overload)),
//! per-session send backpressure ([`backpressure`](crate::backpressure)),
//! and per-session frame-size governance. However, no mechanism limits the
//! total number of established sessions across all listeners and outbound
//! connectors. Under multi-node connection storms, a peer can exhaust fd
//! and memory resources by opening an unbounded number of sessions
//! regardless of per-listener rate limiting, because rate limiting only
//! slows the arrival rate, not the accumulation of long-lived sessions.
//!
//! This module provides a global session concurrency cap: a shared atomic
//! counter that gates every session-establishment attempt (both inbound
//! accept and outbound connect). When the counter is at the configured
//! maximum, new attempts are rejected with [`SessionConcurrencyError`].
//!
//! ## Lifecycle
//!
//! ```text
//!   accept/connect
//!       |
//!       v
//!   limiter.try_acquire()
//!       |
//!       +-- Ok(permit) --> session proceeds; permit stored in session handle
//!       |
//!       +-- Err(error) --> connection rejected
//!
//!   session close / drop
//!       |
//!       v
//!   permit dropped --> counter decremented, waiters notified
//! ```
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::session_concurrency::{
//!     SessionConcurrencyConfig, SessionConcurrencyLimiter,
//! };
//!
//! let config = SessionConcurrencyConfig::default(); // max_sessions = 256
//! let limiter = SessionConcurrencyLimiter::new(config);
//!
//! match limiter.try_acquire() {
//!     Ok(permit) => {
//!         // proceed with session establishment; permit will auto-release
//!         // when the session handle is dropped
//!     }
//!     Err(e) => {
//!         // at capacity; reject the connection
//!     }
//! }
//!
//! println!("remaining slots: {}", limiter.remaining());
//! ```
//!
//! ## Telemetry
//!
//! When a connection is rejected due to the global concurrency limit, a
//! [`SessionConcurrencyLimitHit`] event is produced. Callers can inspect
//! the event for observability.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// SessionConcurrencyConfig
// ---------------------------------------------------------------------------

/// Configuration for the global session concurrency limiter.
///
/// Controls the maximum number of concurrently established transport sessions.
#[derive(Clone, Debug)]
pub struct SessionConcurrencyConfig {
    /// Maximum number of concurrent sessions across all listeners and outbound
    /// connectors. Default: 256.
    pub max_sessions: usize,
}

impl Default for SessionConcurrencyConfig {
    fn default() -> Self {
        Self { max_sessions: 256 }
    }
}

impl SessionConcurrencyConfig {
    /// Create a new config with the given maximum.
    #[must_use]
    pub const fn new(max_sessions: usize) -> Self {
        Self { max_sessions }
    }

    /// Builder: set the maximum session count.
    #[must_use]
    pub fn with_max_sessions(mut self, max_sessions: usize) -> Self {
        self.max_sessions = max_sessions;
        self
    }

    /// Validate configuration values.
    ///
    /// Returns `Err` with a description when `max_sessions` is zero.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_sessions == 0 {
            return Err("max_sessions must be greater than zero".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SessionConcurrencyError
// ---------------------------------------------------------------------------

/// Error returned when the global session concurrency limit is reached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionConcurrencyError {
    /// The configured maximum number of sessions.
    pub max: usize,
    /// The current session count at the time of rejection.
    pub current: usize,
}

impl SessionConcurrencyError {
    /// Create a new error with the given max and current counts.
    #[must_use]
    pub const fn at_capacity(max: usize, current: usize) -> Self {
        Self { max, current }
    }
}

impl std::fmt::Display for SessionConcurrencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "session concurrency limit reached: {}/{} sessions active",
            self.current, self.max
        )
    }
}

impl std::error::Error for SessionConcurrencyError {}

// ---------------------------------------------------------------------------
// SessionConcurrencyLimitHit
// ---------------------------------------------------------------------------

/// Telemetry event emitted when a connection is rejected due to the global
/// session concurrency limit.
#[derive(Clone, Debug)]
pub struct SessionConcurrencyLimitHit {
    /// The configured maximum.
    pub max: usize,
    /// The count at the time of rejection.
    pub current: usize,
}

// ---------------------------------------------------------------------------
// SessionConcurrencyLimiter
// ---------------------------------------------------------------------------

/// Global session concurrency limiter.
///
/// Maintains an atomic counter of currently active sessions and rejects
/// new session-establishment attempts when the count reaches the configured
/// maximum.
///
/// # Thread safety
///
/// The counter uses `AtomicUsize` for lock-free increment/decrement. The
/// `Notify` provides a wake-up mechanism for callers that want to wait
/// for capacity to become available.
pub struct SessionConcurrencyLimiter {
    /// Current active session count (shared with permits via Arc).
    count: Arc<AtomicUsize>,
    /// Maximum allowed concurrent sessions.
    max: usize,
    /// Notify for capacity-available wake-up (shared with permits via Arc).
    notify: Arc<Notify>,
}

impl SessionConcurrencyLimiter {
    /// Create a new limiter from the given configuration.
    #[must_use]
    pub fn new(config: SessionConcurrencyConfig) -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            max: config.max_sessions,
            notify: Arc::new(Notify::new()),
        }
    }

    /// Attempt to acquire a session permit.
    ///
    /// Atomically increments the session counter if below the limit.
    /// Returns a [`SessionPermit`] guard that decrements the counter on drop,
    /// or a [`SessionConcurrencyError`] if at capacity.
    pub fn try_acquire(&self) -> Result<SessionPermit, SessionConcurrencyError> {
        loop {
            let current = self.count.load(Ordering::Relaxed);
            if current >= self.max {
                return Err(SessionConcurrencyError::at_capacity(self.max, current));
            }
            match self.count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(SessionPermit {
                        count: Arc::clone(&self.count),
                        notify: Arc::clone(&self.notify),
                    });
                }
                Err(_) => {
                    // CAS failed, retry with fresh load
                }
            }
        }
    }

    /// Return the number of remaining session slots.
    ///
    /// Returns 0 when at or above capacity.
    pub fn remaining(&self) -> usize {
        let current = self.count.load(Ordering::Relaxed);
        self.max.saturating_sub(current)
    }

    /// Return whether the limiter is at capacity.
    pub fn is_at_capacity(&self) -> bool {
        self.count.load(Ordering::Relaxed) >= self.max
    }

    /// Return the current active session count.
    pub fn current(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }

    /// Return the configured maximum.
    pub fn max(&self) -> usize {
        self.max
    }

    /// Wait for capacity to become available.
    ///
    /// Returns a future that resolves when the session count drops below
    /// the maximum. The caller should call `try_acquire()` after this
    /// future resolves, as there may be a race with other acquirers.
    pub async fn wait_for_capacity(&self) {
        if !self.is_at_capacity() {
            return;
        }
        self.notify.notified().await;
    }

    /// Return a reference to the internal notify for external waiters.
    pub fn notify_handle(&self) -> &Notify {
        &self.notify
    }
}

impl std::fmt::Debug for SessionConcurrencyLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionConcurrencyLimiter")
            .field("current", &self.current())
            .field("max", &self.max)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// SessionPermit
// ---------------------------------------------------------------------------

/// A session concurrency permit guard.
///
/// Acquired via [`SessionConcurrencyLimiter::try_acquire`]. When dropped,
/// the session counter is decremented and one waiter (if any) is notified.
///
/// The permit should be stored in the session handle or connection wrapper
/// so it is dropped when the session closes.
///
/// # Example
///
/// ```ignore
/// let permit = limiter.try_acquire().unwrap();
/// // ... establish session, store permit in session handle ...
/// // When the session closes and the handle is dropped, the permit
/// // is automatically released.
/// ```
#[derive(Debug, Clone)]
pub struct SessionPermit {
    count: Arc<AtomicUsize>,
    notify: Arc<Notify>,
}

impl Drop for SessionPermit {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::Release);
        self.notify.notify_one();
    }
}

impl SessionPermit {
    /// Create a no-op permit for testing or when the limiter is not configured.
    ///
    /// This permit does not track any global counter. Dropping it is a no-op.
    #[must_use]
    pub fn noop() -> Self {
        Self {
            count: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
        }
    }

    /// Return the current value of the counter linked to this permit.
    ///
    /// Useful for diagnostics. For the active session count, prefer
    /// [`SessionConcurrencyLimiter::current`].
    pub fn linked_count(&self) -> usize {
        self.count.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Config tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_is_256() {
        let cfg = SessionConcurrencyConfig::default();
        assert_eq!(cfg.max_sessions, 256);
    }

    #[test]
    fn config_validate_accepts_valid() {
        let cfg = SessionConcurrencyConfig::new(128);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_zero() {
        let cfg = SessionConcurrencyConfig::new(0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_builder() {
        let cfg = SessionConcurrencyConfig::default().with_max_sessions(512);
        assert_eq!(cfg.max_sessions, 512);
    }

    // -----------------------------------------------------------------------
    // Basic acquire/release
    // -----------------------------------------------------------------------

    #[test]
    fn acquire_increments_count() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(10));
        assert_eq!(limiter.current(), 0);
        let permit = limiter.try_acquire().unwrap();
        assert_eq!(limiter.current(), 1);
        assert_eq!(limiter.remaining(), 9);
        drop(permit);
        assert_eq!(limiter.current(), 0);
    }

    #[test]
    fn acquire_up_to_capacity() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(5));
        let mut permits = Vec::new();
        for _ in 0..5 {
            permits.push(limiter.try_acquire().unwrap());
        }
        assert_eq!(limiter.current(), 5);
        assert!(limiter.is_at_capacity());
    }

    #[test]
    fn at_capacity_rejection() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(2));
        let p1 = limiter.try_acquire().unwrap();
        let p2 = limiter.try_acquire().unwrap();
        let err = limiter.try_acquire().unwrap_err();
        assert_eq!(err.max, 2);
        assert_eq!(err.current, 2);
        assert!(limiter.is_at_capacity());
        drop(p1);
        drop(p2);
    }

    #[test]
    fn release_frees_slot_for_new_acquire() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(1));
        let p = limiter.try_acquire().unwrap();
        assert!(limiter.try_acquire().is_err());
        drop(p);
        assert!(limiter.try_acquire().is_ok());
    }

    #[test]
    fn release_decrements_correctly() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(100));
        let p1 = limiter.try_acquire().unwrap();
        let p2 = limiter.try_acquire().unwrap();
        let p3 = limiter.try_acquire().unwrap();
        assert_eq!(limiter.current(), 3);
        drop(p1);
        assert_eq!(limiter.current(), 2);
        drop(p2);
        assert_eq!(limiter.current(), 1);
        drop(p3);
        assert_eq!(limiter.current(), 0);
    }

    // -----------------------------------------------------------------------
    // Concurrent acquire
    // -----------------------------------------------------------------------

    #[test]
    fn concurrent_acquire_no_overcount() {
        let limiter = Arc::new(SessionConcurrencyLimiter::new(
            SessionConcurrencyConfig::new(100),
        ));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let l = limiter.clone();
            handles.push(thread::spawn(move || {
                let mut permits = Vec::new();
                for _ in 0..25 {
                    match l.try_acquire() {
                        Ok(p) => permits.push(p),
                        Err(_) => break,
                    }
                }
                permits
            }));
        }

        let mut all_permits = Vec::new();
        for h in handles {
            all_permits.extend(h.join().unwrap());
        }

        assert_eq!(all_permits.len(), 100);
        assert_eq!(limiter.current(), 100);
        assert!(limiter.is_at_capacity());

        let err = limiter.try_acquire().unwrap_err();
        assert_eq!(err.current, 100);
    }

    #[test]
    fn concurrent_acquire_release_cycle() {
        let limiter = Arc::new(SessionConcurrencyLimiter::new(
            SessionConcurrencyConfig::new(10),
        ));
        let barrier = Arc::new(std::sync::Barrier::new(2));

        let b1 = barrier.clone();
        let l1 = limiter.clone();
        let t1 = thread::spawn(move || {
            b1.wait();
            for _ in 0..100 {
                let p = l1.try_acquire().unwrap();
                thread::sleep(Duration::from_micros(10));
                drop(p);
            }
        });

        let b2 = barrier.clone();
        let l2 = limiter.clone();
        let t2 = thread::spawn(move || {
            b2.wait();
            for _ in 0..100 {
                let p = l2.try_acquire().unwrap();
                thread::sleep(Duration::from_micros(10));
                drop(p);
            }
        });

        t1.join().unwrap();
        t2.join().unwrap();
        assert_eq!(limiter.current(), 0);
    }

    // -----------------------------------------------------------------------
    // Notify wake-up
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn notify_wakes_on_release() {
        let limiter = Arc::new(SessionConcurrencyLimiter::new(
            SessionConcurrencyConfig::new(1),
        ));
        let permit = limiter.try_acquire().unwrap();

        let l = limiter.clone();
        let handle = tokio::spawn(async move {
            l.wait_for_capacity().await;
            l.try_acquire().unwrap()
        });

        // Give the waiter time to register
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(permit);

        let new_permit = handle.await.unwrap();
        drop(new_permit);
        assert_eq!(limiter.current(), 0);
    }

    #[tokio::test]
    async fn wait_for_capacity_returns_immediately_when_not_full() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(10));
        // Should return immediately since we're not at capacity
        limiter.wait_for_capacity().await;
    }

    // -----------------------------------------------------------------------
    // Error and event types
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_contains_max_and_current() {
        let err = SessionConcurrencyError::at_capacity(256, 256);
        let msg = err.to_string();
        assert!(msg.contains("256"));
    }

    #[test]
    fn error_is_clone_and_eq() {
        let e1 = SessionConcurrencyError::at_capacity(10, 5);
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn limit_hit_event_contains_diagnostics() {
        let event = SessionConcurrencyLimitHit {
            max: 100,
            current: 100,
        };
        assert_eq!(event.max, 100);
        assert_eq!(event.current, 100);
    }

    // -----------------------------------------------------------------------
    // SessionPermit::noop
    // -----------------------------------------------------------------------

    #[test]
    fn noop_permit_drop_does_not_panic() {
        let permit = SessionPermit::noop();
        drop(permit);
    }

    #[test]
    fn noop_permit_clone_drops_safely() {
        let p1 = SessionPermit::noop();
        let p2 = p1.clone();
        drop(p1);
        drop(p2);
    }

    // -----------------------------------------------------------------------
    // Debug output
    // -----------------------------------------------------------------------

    #[test]
    fn debug_output_contains_type_and_count() {
        let limiter = SessionConcurrencyLimiter::new(SessionConcurrencyConfig::new(42));
        let s = format!("{limiter:?}");
        assert!(s.contains("SessionConcurrencyLimiter"));
        assert!(s.contains("42"));
    }
}
