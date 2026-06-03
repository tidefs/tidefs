//! Listener overload protection with token-bucket accept-rate limiting and
//! concurrent-pending-handshake bounding.
//!
//! This module prevents unbounded connection acceptance under connection
//! floods, partition-rejoin storms, or multi-node boot races by enforcing
//! two independent guards on the listener accept path:
//!
//! 1. **Token-bucket rate limiter** (`AcceptRateLimiter`): gates the accept
//!    call itself, bounding the sustained accept rate to `accept_rate_per_sec`
//!    with a 2× burst allowance. Tokens are refilled on each check based on
//!    elapsed wall-clock time.
//! 2. **Pending-handshake counter** (`PendingAcceptCounter`): bounds the
//!    number of concurrently accepted-but-not-yet-established connections.
//!    The counter is incremented after a successful accept and decremented
//!    when the handshake completes (or fails). Accepts are rejected when the
//!    count reaches `max_pending_handshakes`.
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::listener_overload::{
//!     AcceptRateLimiter, ListenerOverloadConfig, PendingAcceptCounter,
//!     ConnectionRejectedReason, OverloadGuard,
//! };
//!
//! let config = ListenerOverloadConfig::default();
//! let guard = OverloadGuard::new(&config);
//!
//! // Before accept:
//! guard.pre_accept()?;
//! // After accept, before handshake spawn:
//! guard.post_accept(peer_addr)?;
//! // ... handshake ...
//! guard.release();
//! ```
//!
//! ## Telemetry
//!
//! Rejected connections emit events through an `OverloadEventSubscriber`
//! callback registered on the `OverloadGuard`. The event carries the
//! rejection reason and peer address for operator observability.
//!
//! ## Integration
//!
//! The [`TransportListener`](crate::listener::TransportListener) optionally
//! enables overload protection via `with_overload_protection(config)`. When
//! enabled, both guards are applied on every `accept()` call.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

// ---------------------------------------------------------------------------
// ListenerOverloadConfig
// ---------------------------------------------------------------------------

/// Configuration for listener overload protection.
///
/// Two independent guards:
/// - `max_pending_handshakes`: bounds concurrent accepted-but-not-yet-established
///   connections (default 64).
/// - `accept_rate_per_sec`: sustained token-bucket accept rate with 2× burst
///   (default 100.0).
#[derive(Clone, Debug)]
pub struct ListenerOverloadConfig {
    /// Maximum number of concurrently accepted connections that have not yet
    /// completed session establishment (handshake). New accepts are rejected
    /// when this bound is reached.
    pub max_pending_handshakes: usize,

    /// Sustained accept rate in accepts per second. The token bucket refills
    /// at this rate with a burst capacity of 2× this value.
    pub accept_rate_per_sec: f64,
}

impl Default for ListenerOverloadConfig {
    fn default() -> Self {
        Self {
            max_pending_handshakes: 64,
            accept_rate_per_sec: 100.0,
        }
    }
}

impl ListenerOverloadConfig {
    /// Validate configuration values.
    ///
    /// Returns `Err` with a description when any value is zero or negative.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_pending_handshakes == 0 {
            return Err("max_pending_handshakes must be greater than zero".into());
        }
        if self.accept_rate_per_sec <= 0.0 {
            return Err("accept_rate_per_sec must be greater than zero".into());
        }
        Ok(())
    }

    /// Burst capacity: 2× the sustained rate, minimum 1.
    pub fn burst_capacity(&self) -> f64 {
        (self.accept_rate_per_sec * 2.0).max(1.0)
    }
}

// ---------------------------------------------------------------------------
// ConnectionRejectedReason
// ---------------------------------------------------------------------------

/// Reason a connection was rejected by listener overload protection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectionRejectedReason {
    /// Token-bucket accept rate limit was exceeded.
    RateLimitExceeded,
    /// Maximum pending handshake count was reached.
    PendingHandshakeLimitExceeded,
}

impl std::fmt::Display for ConnectionRejectedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimitExceeded => write!(f, "RateLimitExceeded"),
            Self::PendingHandshakeLimitExceeded => write!(f, "PendingHandshakeLimitExceeded"),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionRejectedEvent
// ---------------------------------------------------------------------------

/// Telemetry event emitted when a connection is rejected by overload protection.
#[derive(Clone, Debug)]
pub struct ConnectionRejectedEvent {
    /// Reason for rejection.
    pub reason: ConnectionRejectedReason,
    /// Peer socket address (available for pending-handshake rejections; may
    /// be absent for rate-limit rejections that occur before accept).
    pub peer_addr: Option<SocketAddr>,
}

// ---------------------------------------------------------------------------
// OverloadEventSubscriber
// ---------------------------------------------------------------------------

/// Callback for listener overload telemetry events.
///
/// Register implementations to receive `ConnectionRejectedEvent` notifications
/// for operator observability of overload conditions.
pub trait OverloadEventSubscriber: Send + Sync {
    /// Called when a connection is rejected by overload protection.
    fn on_connection_rejected(&self, event: &ConnectionRejectedEvent);
}

// ---------------------------------------------------------------------------
// AcceptRateLimiter
// ---------------------------------------------------------------------------

/// Token-bucket accept rate limiter.
///
/// Maintains a floating-point token count that refills at `rate` tokens per
/// second (burst capacity = 2× rate). Each `check()` call consumes one token
/// if available; otherwise the check fails.
///
/// All state updates use atomics. The token count is stored as a fixed-point
/// integer (micro-tokens) to avoid floating-point atomics.
pub struct AcceptRateLimiter {
    /// Tokens available, stored as micro-tokens (tokens × 1_000_000).
    tokens: AtomicU64,
    /// Maximum token capacity in micro-tokens.
    max_tokens: u64,
    /// Refill rate in micro-tokens per second.
    rate_micro: u64,
    /// Timestamp of the last refill (monotonic microseconds).
    last_refill_s: AtomicU64,
    /// Whether the limiter is enabled. When false, all checks pass.
    enabled: AtomicBool,
}

impl AcceptRateLimiter {
    /// Create a new rate limiter with the given sustained rate (accepts/sec).
    ///
    /// The bucket starts full (burst capacity = 2× rate).
    /// Pass `rate <= 0.0` to create a disabled limiter that always passes.
    pub fn new(rate_per_sec: f64) -> Self {
        if rate_per_sec <= 0.0 {
            return Self {
                tokens: AtomicU64::new(0),
                max_tokens: 0,
                rate_micro: 0,
                last_refill_s: AtomicU64::new(0),
                enabled: AtomicBool::new(false),
            };
        }
        let burst = (rate_per_sec * 2.0).max(1.0);
        let rate_micro = (rate_per_sec * 1_000_000.0) as u64;
        let max_tokens = (burst * 1_000_000.0) as u64;
        Self {
            tokens: AtomicU64::new(max_tokens),
            max_tokens,
            rate_micro,
            last_refill_s: AtomicU64::new(monotonic_micros()),
            enabled: AtomicBool::new(true),
        }
    }

    /// Check whether a token is available for one accept.
    ///
    /// Returns `true` if the accept should proceed, `false` if the rate
    /// limit has been exceeded.
    ///
    /// On each call, tokens are refilled based on elapsed time since the
    /// last refill. Then one token is consumed if available.
    pub fn check(&self) -> bool {
        if !self.enabled.load(Ordering::Relaxed) {
            return true;
        }
        self.refill();
        self.consume()
    }

    /// Refill tokens based on elapsed time since the last refill.
    fn refill(&self) {
        let now = monotonic_micros();
        let last = self.last_refill_s.load(Ordering::Relaxed);
        let elapsed = now.saturating_sub(last);
        if elapsed == 0 {
            return;
        }

        // Try to CAS the timestamp forward to claim the refill.
        // On failure another thread already refilled; skip.
        if self
            .last_refill_s
            .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let added = (elapsed as u128 * self.rate_micro as u128) / 1_000_000u128;
        let added = (added as u64).min(self.max_tokens);
        if added > 0 {
            let mut current = self.tokens.load(Ordering::Relaxed);
            loop {
                let new = (current + added).min(self.max_tokens);
                match self.tokens.compare_exchange_weak(
                    current,
                    new,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(c) => current = c,
                }
            }
        }
    }

    /// Consume one token if available.
    fn consume(&self) -> bool {
        let one_micro = 1_000_000u64;
        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current < one_micro {
                return false;
            }
            let new = current - one_micro;
            match self.tokens.compare_exchange_weak(
                current,
                new,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(c) => {
                    if c < one_micro {
                        return false;
                    }
                    // continue loop, retry with fresh load
                }
            }
        }
    }

    /// Return the current number of available tokens (in whole tokens,
    /// rounded down).
    pub fn available_tokens(&self) -> u64 {
        self.tokens.load(Ordering::Relaxed) / 1_000_000
    }

    /// Return the burst capacity in whole tokens.
    pub fn capacity(&self) -> u64 {
        self.max_tokens / 1_000_000
    }

    /// Whether the rate limiter is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed)
    }
}

impl std::fmt::Debug for AcceptRateLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcceptRateLimiter")
            .field("enabled", &self.is_enabled())
            .field("available", &self.available_tokens())
            .field("capacity", &self.capacity())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// PendingAcceptCounter
// ---------------------------------------------------------------------------

/// Bounds the number of concurrent accepted-but-not-yet-established connections.
///
/// Thread-safe via atomic counter. `try_acquire()` increments the counter if
/// below the limit; `release()` decrements it.
pub struct PendingAcceptCounter {
    /// Current count of pending handshakes.
    count: AtomicU64,
    /// Maximum allowed pending handshakes.
    max: u64,
}

/// The pending-handshake counter has reached its configured limit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingAcceptLimitReached;

impl PendingAcceptCounter {
    /// Create a new counter with the given limit.
    ///
    /// Panics if `max` is zero.
    pub fn new(max: usize) -> Self {
        assert!(max > 0, "max_pending_handshakes must be greater than zero");
        Self {
            count: AtomicU64::new(0),
            max: max as u64,
        }
    }

    /// Attempt to acquire a pending-handshake slot.
    ///
    /// Returns `Ok(())` if the counter is below the limit, or
    /// `Err(PendingAcceptLimitReached)` if the limit has been reached.
    pub fn try_acquire(&self) -> Result<(), PendingAcceptLimitReached> {
        loop {
            let current = self.count.load(Ordering::Relaxed);
            if current >= self.max {
                return Err(PendingAcceptLimitReached);
            }
            if self
                .count
                .compare_exchange_weak(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    /// Release a pending-handshake slot.
    ///
    /// Must be called after handshake completion or failure.
    pub fn release(&self) {
        self.count.fetch_sub(1, Ordering::Release);
    }

    /// Return the current pending count.
    pub fn current(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Return the configured limit.
    pub fn max(&self) -> u64 {
        self.max
    }

    /// Whether the counter is at capacity.
    pub fn is_full(&self) -> bool {
        self.current() >= self.max
    }
}

impl std::fmt::Debug for PendingAcceptCounter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingAcceptCounter")
            .field("current", &self.current())
            .field("max", &self.max)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// OverloadGuard
// ---------------------------------------------------------------------------

/// Combined overload guard holding both the rate limiter and pending counter
/// plus optional telemetry subscribers.
///
/// This is the integration point for the listener accept path. Callers
/// invoke `pre_accept()` before the accept call and `post_accept()` after
/// a successful accept.
pub struct OverloadGuard {
    rate_limiter: AcceptRateLimiter,
    pending_counter: PendingAcceptCounter,
    subscribers: Mutex<Vec<Arc<dyn OverloadEventSubscriber>>>,
}

impl OverloadGuard {
    /// Create a new guard from the given configuration.
    pub fn new(config: &ListenerOverloadConfig) -> Self {
        Self {
            rate_limiter: AcceptRateLimiter::new(config.accept_rate_per_sec),
            pending_counter: PendingAcceptCounter::new(config.max_pending_handshakes),
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Register a telemetry subscriber.
    pub fn subscribe(&self, subscriber: Arc<dyn OverloadEventSubscriber>) {
        if let Ok(mut subs) = self.subscribers.lock() {
            subs.push(subscriber);
        }
    }

    /// Pre-accept check: verifies the token-bucket rate limiter.
    ///
    /// Returns `Ok(())` if the accept should proceed, or `Err(reason)` if
    /// the rate limit has been exceeded.
    pub fn pre_accept(&self) -> Result<(), ConnectionRejectedReason> {
        if !self.rate_limiter.check() {
            let event = ConnectionRejectedEvent {
                reason: ConnectionRejectedReason::RateLimitExceeded,
                peer_addr: None,
            };
            self.emit(&event);
            return Err(ConnectionRejectedReason::RateLimitExceeded);
        }
        Ok(())
    }

    /// Post-accept check: verifies the pending-handshake counter.
    ///
    /// Call this after a successful `TcpListener::accept()`. On success,
    /// the caller owns a pending-handshake slot and must call `release()`
    /// after handshake completion or failure.
    ///
    /// Returns `Ok(())` if a slot was acquired, or `Err(reason)` if the
    /// pending-handshake limit has been reached, along with the peer address.
    pub fn post_accept(&self, peer_addr: SocketAddr) -> Result<(), ConnectionRejectedReason> {
        match self.pending_counter.try_acquire() {
            Ok(()) => Ok(()),
            Err(PendingAcceptLimitReached) => {
                let event = ConnectionRejectedEvent {
                    reason: ConnectionRejectedReason::PendingHandshakeLimitExceeded,
                    peer_addr: Some(peer_addr),
                };
                self.emit(&event);
                Err(ConnectionRejectedReason::PendingHandshakeLimitExceeded)
            }
        }
    }

    /// Release a pending-handshake slot.
    pub fn release(&self) {
        self.pending_counter.release();
    }

    /// Return the number of currently pending handshakes.
    pub fn pending_count(&self) -> u64 {
        self.pending_counter.current()
    }

    /// Return the rate limiter's available tokens.
    pub fn available_tokens(&self) -> u64 {
        self.rate_limiter.available_tokens()
    }

    /// Return a reference to the rate limiter (for testing).
    pub fn rate_limiter(&self) -> &AcceptRateLimiter {
        &self.rate_limiter
    }

    /// Return a reference to the pending counter (for testing).
    pub fn pending_counter(&self) -> &PendingAcceptCounter {
        &self.pending_counter
    }

    fn emit(&self, event: &ConnectionRejectedEvent) {
        if let Ok(subs) = self.subscribers.lock() {
            for sub in subs.iter() {
                sub.on_connection_rejected(event);
            }
        }
    }
}

impl std::fmt::Debug for OverloadGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OverloadGuard")
            .field("rate_limiter", &self.rate_limiter)
            .field("pending_counter", &self.pending_counter)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Approximate monotonic time in microseconds, anchored to process start.
fn monotonic_micros() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    let elapsed = base.elapsed();
    elapsed.as_micros() as u64
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::thread;
    use std::time::Duration;

    // -----------------------------------------------------------------------
    // Config tests
    // -----------------------------------------------------------------------

    #[test]
    fn config_defaults_are_sensible() {
        let cfg = ListenerOverloadConfig::default();
        assert_eq!(cfg.max_pending_handshakes, 64);
        assert!((cfg.accept_rate_per_sec - 100.0).abs() < f64::EPSILON);
    }

    #[test]
    fn config_validate_accepts_valid_values() {
        let cfg = ListenerOverloadConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validate_rejects_zero_max_pending() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 0,
            accept_rate_per_sec: 100.0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_zero_rate() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 64,
            accept_rate_per_sec: 0.0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validate_rejects_negative_rate() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 64,
            accept_rate_per_sec: -1.0,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_burst_capacity_is_double_rate() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 64,
            accept_rate_per_sec: 50.0,
        };
        assert_eq!(cfg.burst_capacity(), 100.0);
    }

    #[test]
    fn config_burst_capacity_minimum_one() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 64,
            accept_rate_per_sec: 0.1,
        };
        assert_eq!(cfg.burst_capacity(), 1.0);
    }

    // -----------------------------------------------------------------------
    // AcceptRateLimiter tests
    // -----------------------------------------------------------------------

    #[test]
    fn rate_limiter_starts_with_full_burst() {
        let limiter = AcceptRateLimiter::new(100.0);
        assert!(limiter.is_enabled());
        assert_eq!(limiter.capacity(), 200);
        assert!(limiter.available_tokens() >= 190);
    }

    #[test]
    fn rate_limiter_disabled_with_zero_rate() {
        let limiter = AcceptRateLimiter::new(0.0);
        assert!(!limiter.is_enabled());
        for _ in 0..1000 {
            assert!(limiter.check());
        }
    }

    #[test]
    fn rate_limiter_consumes_tokens() {
        let limiter = AcceptRateLimiter::new(100.0);
        let initial = limiter.available_tokens();
        assert!(initial > 0);
        let mut passes = 0;
        for _ in 0..initial as usize {
            if limiter.check() {
                passes += 1;
            }
        }
        assert!(passes > 0);
        let after = limiter.available_tokens();
        assert!(after < initial || passes < initial as usize);
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let limiter = AcceptRateLimiter::new(1000.0);
        while limiter.check() {}
        assert_eq!(limiter.available_tokens(), 0);
        thread::sleep(Duration::from_millis(50));
        let available = limiter.available_tokens();
        assert!(
            available > 0,
            "should have refilled after 50ms, got {available}"
        );
    }

    #[test]
    fn rate_limiter_burst_behavior() {
        let limiter = AcceptRateLimiter::new(10.0);
        let mut count = 0;
        for _ in 0..50 {
            if limiter.check() {
                count += 1;
            }
        }
        assert!(
            count >= 15,
            "expected at least 15 burst tokens, got {count}"
        );
        assert!(count < 50, "should not pass all 50 without refill");
    }

    #[test]
    fn rate_limiter_check_is_thread_safe() {
        let limiter = Arc::new(AcceptRateLimiter::new(1000.0));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let l = limiter.clone();
            handles.push(thread::spawn(move || {
                let mut passes = 0;
                for _ in 0..100 {
                    if l.check() {
                        passes += 1;
                    }
                }
                passes
            }));
        }
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert!(total > 0, "at least some should pass");
    }

    // -----------------------------------------------------------------------
    // PendingAcceptCounter tests
    // -----------------------------------------------------------------------

    #[test]
    fn pending_counter_acquire_up_to_limit() {
        let counter = PendingAcceptCounter::new(5);
        for _ in 0..5 {
            assert!(counter.try_acquire().is_ok());
        }
        assert_eq!(counter.current(), 5);
        assert!(counter.is_full());
    }

    #[test]
    fn pending_counter_rejects_beyond_limit() {
        let counter = PendingAcceptCounter::new(3);
        assert!(counter.try_acquire().is_ok());
        assert!(counter.try_acquire().is_ok());
        assert!(counter.try_acquire().is_ok());
        assert!(counter.try_acquire().is_err());
    }

    #[test]
    fn pending_counter_release_frees_slot() {
        let counter = PendingAcceptCounter::new(2);
        assert!(counter.try_acquire().is_ok());
        assert!(counter.try_acquire().is_ok());
        assert!(counter.try_acquire().is_err());
        counter.release();
        assert_eq!(counter.current(), 1);
        assert!(!counter.is_full());
        assert!(counter.try_acquire().is_ok());
        assert_eq!(counter.current(), 2);
    }

    #[test]
    fn pending_counter_release_no_panic_when_empty() {
        let counter = PendingAcceptCounter::new(5);
        counter.release();
        counter.release();
        let _ = counter.current();
    }

    #[test]
    fn pending_counter_thread_safety() {
        let counter = Arc::new(PendingAcceptCounter::new(100));
        let mut handles = Vec::new();
        let c = counter.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                while c.try_acquire().is_err() {
                    thread::yield_now();
                }
                thread::sleep(Duration::from_micros(10));
                c.release();
            }
        }));
        let c = counter.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..50 {
                while c.try_acquire().is_err() {
                    thread::yield_now();
                }
                thread::sleep(Duration::from_micros(10));
                c.release();
            }
        }));
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(counter.current(), 0);
    }

    #[test]
    fn pending_counter_max_returns_limit() {
        let counter = PendingAcceptCounter::new(42);
        assert_eq!(counter.max(), 42);
    }

    // -----------------------------------------------------------------------
    // OverloadGuard integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn guard_pre_accept_passes_when_tokens_available() {
        let cfg = ListenerOverloadConfig::default();
        let guard = OverloadGuard::new(&cfg);
        assert!(guard.pre_accept().is_ok());
    }

    #[test]
    fn guard_post_accept_acquires_slot() {
        let cfg = ListenerOverloadConfig::default();
        let guard = OverloadGuard::new(&cfg);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(guard.post_accept(addr).is_ok());
        assert_eq!(guard.pending_count(), 1);
        guard.release();
        assert_eq!(guard.pending_count(), 0);
    }

    #[test]
    fn guard_post_accept_rejects_when_full() {
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 1,
            accept_rate_per_sec: 100.0,
        };
        let guard = OverloadGuard::new(&cfg);
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(guard.post_accept(addr).is_ok());
        let addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let result = guard.post_accept(addr2);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ConnectionRejectedReason::PendingHandshakeLimitExceeded
        );
    }

    #[test]
    fn guard_emits_telemetry_on_rejection() {
        use std::sync::Mutex as StdMutex;
        struct TestSub {
            events: StdMutex<Vec<ConnectionRejectedEvent>>,
        }
        impl OverloadEventSubscriber for TestSub {
            fn on_connection_rejected(&self, event: &ConnectionRejectedEvent) {
                self.events.lock().unwrap().push(event.clone());
            }
        }
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 1,
            accept_rate_per_sec: 100.0,
        };
        let guard = OverloadGuard::new(&cfg);
        let sub = Arc::new(TestSub {
            events: StdMutex::new(Vec::new()),
        });
        guard.subscribe(sub.clone());
        let addr: SocketAddr = "127.0.0.1:12345".parse().unwrap();
        assert!(guard.post_accept(addr).is_ok());
        let addr2: SocketAddr = "127.0.0.1:12346".parse().unwrap();
        let _ = guard.post_accept(addr2);
        let events = sub.events.lock().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].reason,
            ConnectionRejectedReason::PendingHandshakeLimitExceeded
        );
        assert_eq!(events[0].peer_addr, Some(addr2));
    }

    #[test]
    fn guard_telemetry_rate_limit_event_has_no_addr() {
        struct CountingSub {
            count: AtomicUsize,
        }
        impl OverloadEventSubscriber for CountingSub {
            fn on_connection_rejected(&self, event: &ConnectionRejectedEvent) {
                self.count.fetch_add(1, Ordering::Relaxed);
                assert_eq!(event.peer_addr, None);
                assert_eq!(event.reason, ConnectionRejectedReason::RateLimitExceeded);
            }
        }
        let cfg = ListenerOverloadConfig {
            max_pending_handshakes: 64,
            accept_rate_per_sec: 1.0,
        };
        let guard = OverloadGuard::new(&cfg);
        let sub = Arc::new(CountingSub {
            count: AtomicUsize::new(0),
        });
        guard.subscribe(sub.clone());
        let mut rejected = 0;
        for _ in 0..100 {
            if guard.pre_accept().is_err() {
                rejected += 1;
            }
        }
        assert!(rejected > 0, "should have rejected some due to rate limit");
    }

    #[test]
    fn connection_rejected_reason_display() {
        assert_eq!(
            ConnectionRejectedReason::RateLimitExceeded.to_string(),
            "RateLimitExceeded"
        );
        assert_eq!(
            ConnectionRejectedReason::PendingHandshakeLimitExceeded.to_string(),
            "PendingHandshakeLimitExceeded"
        );
    }

    #[test]
    fn debug_outputs_contain_type_names() {
        let cfg = ListenerOverloadConfig::default();
        let guard = OverloadGuard::new(&cfg);
        assert!(format!("{guard:?}").contains("OverloadGuard"));
        assert!(format!("{:?}", guard.rate_limiter()).contains("AcceptRateLimiter"));
        assert!(format!("{:?}", guard.pending_counter()).contains("PendingAcceptCounter"));
    }
}
