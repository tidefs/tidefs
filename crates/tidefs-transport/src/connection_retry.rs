//! Outbound connection retry with exponential backoff and per-peer attempt
//! coalescing.
//!
//! ## Purpose
//!
//! When an outbound TCP connection attempt fails due to a transient reason
//! (peer restart, network flap, temporary port exhaustion), this module
//! retries with configurable exponential backoff instead of surfacing an
//! immediate failure. Concurrent callers targeting the same peer coalesce
//! onto a single shared attempt, preventing thundering-herd connection
//! storms.
//!
//! ## Retry algorithm
//!
//! The backoff duration for attempt `n` (0-indexed) is:
//!
//! ```text
//! backoff_n = min(initial_backoff * multiplier^n, max_backoff)
//! ```
//!
//! After each failed attempt, the caller sleeps for `backoff_n` before
//! retrying. The first attempt (`n=0`) uses zero backoff (immediate).
//!
//! ## Coalescing semantics
//!
//! A [`PeerConnectGate`] ensures that only one outbound TCP `connect()`
//! call is in flight per peer [`SocketAddr`] at any time. Concurrent
//! callers wait for the shared outcome:
//!
//! - **Success**: the primary caller confirms the peer is reachable.
//!   Waiting callers then perform a single `TcpStream::connect()` (no
//!   retry needed) to obtain their own independent connections.
//! - **Failure**: the primary caller exhausts all retries. Waiting
//!   callers receive the terminal [`RetryError`].
//!
//! ## Error classification
//!
//! Errors are classified as retryable or terminal using OS error codes:
//!
//! | Error            | Classification |
//! |------------------|----------------|
//! | `ECONNREFUSED`   | Retryable      |
//! | `ECONNRESET`     | Retryable      |
//! | `ETIMEDOUT`      | Retryable      |
//! | `EHOSTUNREACH`   | Retryable      |
//! | `ENETUNREACH`    | Retryable      |
//! | `EADDRINUSE`     | Retryable      |
//! | `EAGAIN`         | Retryable      |
//! | Everything else  | Terminal       |
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::connection_retry::{RetryConfig, PeerConnectGate, connect_with_retry};
//! use std::net::SocketAddr;
//!
//! let config = RetryConfig::default();
//! let gate = PeerConnectGate::new();
//! let addr: SocketAddr = "192.168.1.1:9000".parse().unwrap();
//!
//! match connect_with_retry(&config, &gate, None, addr).await {
//!     Ok(stream) => { /* use stream */ }
//!     Err(e) => { /* terminal failure after all retries */ }
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::sync::Notify;

// ---------------------------------------------------------------------------
// RetryConfig
// ---------------------------------------------------------------------------

/// Configuration for outbound connection retry behaviour.
///
/// Controls the maximum number of attempts, the backoff formula parameters,
/// and the per-attempt connect timeout.
#[derive(Clone, Debug, PartialEq)]
pub struct RetryConfig {
    /// Maximum number of connection attempts (including the first).
    /// Must be >= 1. Default: 5.
    pub max_attempts: u32,

    /// Initial backoff duration before the second attempt.
    /// The first attempt is immediate (zero backoff). Default: 100 ms.
    pub initial_backoff: Duration,

    /// Hard cap on the computed backoff duration. Default: 30 s.
    pub max_backoff: Duration,

    /// Backoff multiplier applied per attempt.
    /// `backoff = min(initial_backoff * multiplier^attempt, max_backoff)`.
    /// Default: 2.0.
    pub backoff_multiplier: f64,

    /// Per-attempt connect timeout.
    /// Each individual `TcpStream::connect()` call is bounded by this
    /// duration. Default: 5 s.
    pub connect_timeout: Duration,
}

impl RetryConfig {
    /// Create a new `RetryConfig` with the given parameters.
    ///
    /// # Panics
    ///
    /// Panics if `max_attempts` is 0, `initial_backoff` is zero, or
    /// `backoff_multiplier` is not finite and positive.
    #[must_use]
    pub fn new(
        max_attempts: u32,
        initial_backoff: Duration,
        max_backoff: Duration,
        backoff_multiplier: f64,
        connect_timeout: Duration,
    ) -> Self {
        assert!(max_attempts > 0, "max_attempts must be >= 1");
        assert!(
            initial_backoff > Duration::ZERO,
            "initial_backoff must be > 0"
        );
        assert!(
            backoff_multiplier.is_finite() && backoff_multiplier >= 1.0,
            "backoff_multiplier must be finite and >= 1.0"
        );
        Self {
            max_attempts,
            initial_backoff,
            max_backoff,
            backoff_multiplier,
            connect_timeout,
        }
    }

    /// Create a `RetryConfig` with zero retries (single attempt, no backoff).
    #[must_use]
    pub fn no_retry(connect_timeout: Duration) -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(1),
            backoff_multiplier: 1.0,
            connect_timeout,
        }
    }

    /// Compute the backoff duration for a given attempt index (0-based).
    #[must_use]
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        if attempt == 0 {
            return Duration::ZERO;
        }
        let factor = self.backoff_multiplier.powi(attempt as i32 - 1);
        mul_duration_f64(self.initial_backoff, factor).min(self.max_backoff)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_attempts == 0 {
            return Err("max_attempts must be >= 1");
        }
        if self.initial_backoff == Duration::ZERO {
            return Err("initial_backoff must be > 0");
        }
        if self.max_backoff < self.initial_backoff {
            return Err("max_backoff must be >= initial_backoff");
        }
        if !(self.backoff_multiplier.is_finite() && self.backoff_multiplier >= 1.0) {
            return Err("backoff_multiplier must be finite and >= 1.0");
        }
        if self.connect_timeout == Duration::ZERO {
            return Err("connect_timeout must be > 0");
        }
        Ok(())
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(30),
            backoff_multiplier: 2.0,
            connect_timeout: Duration::from_secs(5),
        }
    }
}

// ---------------------------------------------------------------------------
// CoalescedOutcome
// ---------------------------------------------------------------------------

/// Shared outcome of a coalesced connect attempt.
///
/// `Success` means the retry loop connected successfully and waiting
/// callers should perform their own single-attempt `TcpStream::connect()`.
/// `Failed` carries the terminal error for all waiters.
#[derive(Debug, Clone)]
pub(crate) enum CoalescedOutcome {
    Pending,
    Success,
    Failed(Arc<RetryError>),
}

type SharedCoalescedOutcome = Arc<Mutex<CoalescedOutcome>>;
type CoalescedGateEntry = (SharedCoalescedOutcome, Arc<Notify>);

// ---------------------------------------------------------------------------
// PeerConnectGate
// ---------------------------------------------------------------------------

/// Per-peer attempt deduplication gate.
///
/// Ensures that only one outbound TCP `connect()` call is in-flight per
/// peer [`SocketAddr`] at any time. Concurrent callers wait for the shared
/// outcome.
#[derive(Debug, Default)]
pub struct PeerConnectGate {
    entries: Mutex<HashMap<SocketAddr, CoalescedGateEntry>>,
}

impl PeerConnectGate {
    /// Create a new, empty gate.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Try to begin a connect to `peer_addr`.
    ///
    /// Returns `Ok(notify)` if this caller is the primary — it must run
    /// the retry loop and call `complete()` with the outcome.
    ///
    /// Returns `Err((outcome, notify))` if another caller is already
    /// attempting connection — the caller must wait for the outcome.
    pub(crate) fn try_begin(
        &self,
        peer_addr: SocketAddr,
    ) -> Result<CoalescedGateEntry, CoalescedGateEntry> {
        let mut guard = self.entries.lock().unwrap();
        if let Some(entry) = guard.get(&peer_addr) {
            return Err(entry.clone());
        }
        let outcome = Arc::new(Mutex::new(CoalescedOutcome::Pending));
        let notify = Arc::new(Notify::new());
        guard.insert(peer_addr, (Arc::clone(&outcome), Arc::clone(&notify)));
        Ok((outcome, notify))
    }

    /// Complete a connection attempt, waking all waiters and cleaning up.
    pub(crate) fn complete(
        &self,
        peer_addr: SocketAddr,
        outcome: &Arc<Mutex<CoalescedOutcome>>,
        notify: &Arc<Notify>,
        result: CoalescedOutcome,
    ) {
        *outcome.lock().unwrap() = result;
        notify.notify_waiters();
        let mut guard = self.entries.lock().unwrap();
        guard.remove(&peer_addr);
    }

    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// RetryError
// ---------------------------------------------------------------------------

/// Terminal error returned after all retry attempts are exhausted.
#[derive(Debug, Clone)]
pub struct RetryError {
    /// The peer address we were trying to connect to.
    pub peer_addr: SocketAddr,

    /// Total number of attempts made.
    pub attempts: u32,

    /// Classification of the last error.
    pub last_error_kind: std::io::ErrorKind,

    /// Display message for the last error.
    pub last_error_msg: String,

    /// Whether the last error was classified as retryable.
    pub last_error_was_retryable: bool,
}

impl RetryError {
    fn from_io(
        peer_addr: SocketAddr,
        attempts: u32,
        error: std::io::Error,
        last_error_was_retryable: bool,
    ) -> Self {
        Self {
            peer_addr,
            attempts,
            last_error_kind: error.kind(),
            last_error_msg: error.to_string(),
            last_error_was_retryable,
        }
    }
}

impl fmt::Display for RetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "connect to {} failed after {} attempts: {}",
            self.peer_addr, self.attempts, self.last_error_msg
        )
    }
}

impl std::error::Error for RetryError {}

// ---------------------------------------------------------------------------
// Retryable error classification
// ---------------------------------------------------------------------------

/// Returns `true` if the error likely represents a transient condition
/// that may resolve on retry.
#[must_use]
pub fn is_retryable(err: &std::io::Error) -> bool {
    match err.raw_os_error() {
        Some(code) => is_retryable_os_error(code),
        None => matches!(
            err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::NotConnected
                | std::io::ErrorKind::AddrInUse
                | std::io::ErrorKind::WouldBlock
        ),
    }
}

fn is_retryable_os_error(code: i32) -> bool {
    #[allow(non_upper_case_globals)]
    match code {
        c if c == libc::ECONNREFUSED => true,
        c if c == libc::ECONNRESET => true,
        c if c == libc::ETIMEDOUT => true,
        c if c == libc::EHOSTUNREACH => true,
        c if c == libc::ENETUNREACH => true,
        c if c == libc::EADDRINUSE => true,
        c if c == libc::EAGAIN => true,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// connect_with_retry
// ---------------------------------------------------------------------------

/// Establish a TCP connection to `peer_addr` with configurable exponential
/// backoff and per-peer attempt coalescing.
///
/// If another caller is already retrying this peer, this function waits
/// for the shared outcome: on success it does a single `TcpStream::connect()`;
/// on failure it returns the terminal error.
pub async fn connect_with_retry(
    config: &RetryConfig,
    gate: &PeerConnectGate,
    pool: Option<&crate::connection_pool::TcpConnectionPool>,
    peer_addr: SocketAddr,
) -> Result<TcpStream, RetryError> {
    // Check the connection pool first for a reusable connection.
    if let Some(pool) = pool {
        if let Some(handle) = pool.checkout(peer_addr) {
            return Ok(handle.into_stream());
        }
    }

    // Try to become the primary retry loop, or wait on the existing one.
    let (outcome, notify) = match gate.try_begin(peer_addr) {
        Ok((outcome, notify)) => (outcome, notify),
        Err((outcome, notify)) => {
            // Another caller is retrying; wait for the shared outcome.
            loop {
                let state = outcome.lock().unwrap().clone();
                match state {
                    CoalescedOutcome::Pending => {
                        drop(state);
                        notify.notified().await;
                    }
                    CoalescedOutcome::Success => {
                        // Primary succeeded; try pool first, then single connect.
                        if let Some(pool) = pool {
                            if let Some(handle) = pool.checkout(peer_addr) {
                                return Ok(handle.into_stream());
                            }
                        }
                        return single_connect(config.connect_timeout, peer_addr).await;
                    }
                    CoalescedOutcome::Failed(err) => {
                        return Err((*err).clone());
                    }
                }
            }
        }
    };

    // We are the primary retry loop.
    let mut last_err: Option<std::io::Error> = None;
    let mut last_err_retryable = false;

    for attempt in 0..config.max_attempts {
        if attempt > 0 {
            let backoff = config.backoff_for_attempt(attempt);
            tokio::time::sleep(backoff).await;
        }

        match tokio::time::timeout(config.connect_timeout, TcpStream::connect(peer_addr)).await {
            Ok(Ok(stream)) => {
                gate.complete(peer_addr, &outcome, &notify, CoalescedOutcome::Success);
                return Ok(stream);
            }
            Ok(Err(e)) => {
                last_err_retryable = is_retryable(&e);
                last_err = Some(e);

                if !last_err_retryable {
                    break;
                }
            }
            Err(_elapsed) => {
                last_err_retryable = true;
                last_err = Some(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "connect to {} timed out after {:?}",
                        peer_addr, config.connect_timeout
                    ),
                ));
            }
        }
    }

    let err = RetryError::from_io(
        peer_addr,
        config.max_attempts,
        last_err.unwrap_or_else(|| {
            std::io::Error::other("connect retry exhausted with no recorded error")
        }),
        last_err_retryable,
    );

    let err_arc = Arc::new(err);
    gate.complete(
        peer_addr,
        &outcome,
        &notify,
        CoalescedOutcome::Failed(Arc::clone(&err_arc)),
    );
    Err(Arc::try_unwrap(err_arc).unwrap_or_else(|arc| (*arc).clone()))
}

/// Perform a single connection attempt with timeout.
async fn single_connect(timeout: Duration, peer_addr: SocketAddr) -> Result<TcpStream, RetryError> {
    match tokio::time::timeout(timeout, TcpStream::connect(peer_addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(RetryError::from_io(peer_addr, 1, e, false)),
        Err(_elapsed) => Err(RetryError::from_io(
            peer_addr,
            1,
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("connect to {peer_addr} timed out after {timeout:?}"),
            ),
            true,
        )),
    }
}

// ---------------------------------------------------------------------------
// Helper: multiply Duration by f64
// ---------------------------------------------------------------------------

fn mul_duration_f64(d: Duration, factor: f64) -> Duration {
    let nanos = d.as_nanos() as f64 * factor;
    Duration::from_nanos(nanos as u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // RetryConfig tests
    // ------------------------------------------------------------------

    #[test]
    fn retry_config_default_is_valid() {
        let config = RetryConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn retry_config_new_panics_on_zero_attempts() {
        let result = std::panic::catch_unwind(|| {
            RetryConfig::new(
                0,
                Duration::from_millis(100),
                Duration::from_secs(30),
                2.0,
                Duration::from_secs(5),
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn retry_config_new_panics_on_zero_initial_backoff() {
        let result = std::panic::catch_unwind(|| {
            RetryConfig::new(
                3,
                Duration::ZERO,
                Duration::from_secs(30),
                2.0,
                Duration::from_secs(5),
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn retry_config_new_panics_on_negative_multiplier() {
        let result = std::panic::catch_unwind(|| {
            RetryConfig::new(
                3,
                Duration::from_millis(100),
                Duration::from_secs(30),
                -1.0,
                Duration::from_secs(5),
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn retry_config_new_panics_on_sub_one_multiplier() {
        let result = std::panic::catch_unwind(|| {
            RetryConfig::new(
                3,
                Duration::from_millis(100),
                Duration::from_secs(30),
                0.5,
                Duration::from_secs(5),
            )
        });
        assert!(result.is_err());
    }

    #[test]
    fn retry_config_validate_rejects_zero_attempts() {
        let config = RetryConfig {
            max_attempts: 0,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_config_validate_rejects_zero_backoff() {
        let config = RetryConfig {
            initial_backoff: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_config_validate_rejects_max_lt_initial() {
        let config = RetryConfig {
            max_backoff: Duration::from_millis(50),
            initial_backoff: Duration::from_millis(100),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_config_validate_rejects_bad_multiplier() {
        let config = RetryConfig {
            backoff_multiplier: f64::NAN,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_config_validate_rejects_zero_connect_timeout() {
        let config = RetryConfig {
            connect_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn retry_config_no_retry_has_single_attempt() {
        let config = RetryConfig::no_retry(Duration::from_secs(5));
        assert_eq!(config.max_attempts, 1);
        assert_eq!(config.backoff_for_attempt(0), Duration::ZERO);
    }

    // ------------------------------------------------------------------
    // Backoff arithmetic
    // ------------------------------------------------------------------

    #[test]
    fn backoff_for_attempt_zero_is_zero() {
        let config = RetryConfig::default();
        assert_eq!(config.backoff_for_attempt(0), Duration::ZERO);
    }

    #[test]
    fn backoff_for_attempt_one_is_initial() {
        let config = RetryConfig::new(
            5,
            Duration::from_millis(100),
            Duration::from_secs(30),
            2.0,
            Duration::from_secs(5),
        );
        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(100));
    }

    #[test]
    fn backoff_doubles_each_attempt() {
        let config = RetryConfig::new(
            5,
            Duration::from_millis(100),
            Duration::from_secs(30),
            2.0,
            Duration::from_secs(5),
        );
        assert_eq!(config.backoff_for_attempt(0), Duration::ZERO);
        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.backoff_for_attempt(2), Duration::from_millis(200));
        assert_eq!(config.backoff_for_attempt(3), Duration::from_millis(400));
        assert_eq!(config.backoff_for_attempt(4), Duration::from_millis(800));
    }

    #[test]
    fn backoff_respects_max_cap() {
        let config = RetryConfig::new(
            10,
            Duration::from_millis(1000),
            Duration::from_millis(3000),
            2.0,
            Duration::from_secs(5),
        );
        assert_eq!(config.backoff_for_attempt(0), Duration::ZERO);
        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(1000));
        assert_eq!(config.backoff_for_attempt(2), Duration::from_millis(2000));
        assert_eq!(config.backoff_for_attempt(3), Duration::from_millis(3000));
        assert_eq!(config.backoff_for_attempt(4), Duration::from_millis(3000));
    }

    #[test]
    fn backoff_with_multiplier_one_is_constant() {
        let config = RetryConfig::new(
            5,
            Duration::from_millis(500),
            Duration::from_secs(10),
            1.0,
            Duration::from_secs(5),
        );
        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(500));
        assert_eq!(config.backoff_for_attempt(2), Duration::from_millis(500));
        assert_eq!(config.backoff_for_attempt(3), Duration::from_millis(500));
    }

    #[test]
    fn backoff_with_multiplier_three() {
        let config = RetryConfig::new(
            5,
            Duration::from_millis(100),
            Duration::from_secs(30),
            3.0,
            Duration::from_secs(5),
        );
        assert_eq!(config.backoff_for_attempt(1), Duration::from_millis(100));
        assert_eq!(config.backoff_for_attempt(2), Duration::from_millis(300));
        assert_eq!(config.backoff_for_attempt(3), Duration::from_millis(900));
    }

    // ------------------------------------------------------------------
    // Error classification
    // ------------------------------------------------------------------

    #[test]
    fn connection_refused_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        assert!(is_retryable(&err));
    }

    #[test]
    fn connection_reset_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::ECONNRESET);
        assert!(is_retryable(&err));
    }

    #[test]
    fn timed_out_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::ETIMEDOUT);
        assert!(is_retryable(&err));
    }

    #[test]
    fn host_unreachable_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::EHOSTUNREACH);
        assert!(is_retryable(&err));
    }

    #[test]
    fn net_unreachable_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::ENETUNREACH);
        assert!(is_retryable(&err));
    }

    #[test]
    fn addr_in_use_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::EADDRINUSE);
        assert!(is_retryable(&err));
    }

    #[test]
    fn eagain_is_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::EAGAIN);
        assert!(is_retryable(&err));
    }

    #[test]
    fn permission_denied_is_not_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(!is_retryable(&err));
    }

    #[test]
    fn invalid_argument_is_not_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::EINVAL);
        assert!(!is_retryable(&err));
    }

    #[test]
    fn enomem_is_not_retryable() {
        let err = std::io::Error::from_raw_os_error(libc::ENOMEM);
        assert!(!is_retryable(&err));
    }

    #[test]
    fn error_kind_connection_refused_is_retryable() {
        let err = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no listener");
        assert!(is_retryable(&err));
    }

    #[test]
    fn error_kind_other_is_not_retryable() {
        let err = std::io::Error::other("unknown");
        assert!(!is_retryable(&err));
    }

    #[test]
    fn error_kind_would_block_is_retryable() {
        let err = std::io::Error::new(std::io::ErrorKind::WouldBlock, "try again");
        assert!(is_retryable(&err));
    }

    // ------------------------------------------------------------------
    // PeerConnectGate coalescing
    // ------------------------------------------------------------------

    #[test]
    fn peer_connect_gate_first_caller_becomes_owner() {
        let gate = PeerConnectGate::new();
        let addr: SocketAddr = "127.0.0.1:8080".parse().unwrap();
        let result = gate.try_begin(addr);
        assert!(result.is_ok());
        assert_eq!(gate.entry_count(), 1);
    }

    #[test]
    fn peer_connect_gate_second_caller_gets_waiter() {
        let gate = PeerConnectGate::new();
        let addr: SocketAddr = "127.0.0.1:8081".parse().unwrap();
        let _first = gate.try_begin(addr).unwrap();
        let second = gate.try_begin(addr);
        assert!(second.is_err(), "second caller should get waiter");
        assert_eq!(gate.entry_count(), 1);
    }

    #[test]
    fn peer_connect_gate_different_addresses_are_independent() {
        let gate = PeerConnectGate::new();
        let addr1: SocketAddr = "127.0.0.1:8082".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:8083".parse().unwrap();
        assert!(gate.try_begin(addr1).is_ok());
        assert!(gate.try_begin(addr2).is_ok());
        assert_eq!(gate.entry_count(), 2);
    }

    #[test]
    fn peer_connect_gate_complete_cleans_up() {
        let gate = PeerConnectGate::new();
        let addr: SocketAddr = "127.0.0.1:8084".parse().unwrap();
        let (outcome, notify) = gate.try_begin(addr).unwrap();
        let err = RetryError::from_io(
            addr,
            1,
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope"),
            true,
        );
        gate.complete(
            addr,
            &outcome,
            &notify,
            CoalescedOutcome::Failed(Arc::new(err)),
        );
        assert_eq!(gate.entry_count(), 0);
    }

    // ------------------------------------------------------------------
    // RetryError Display
    // ------------------------------------------------------------------

    #[test]
    fn retry_error_display() {
        let err = RetryError::from_io(
            "127.0.0.1:9999".parse().unwrap(),
            5,
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "test error"),
            true,
        );
        let msg = format!("{err}");
        assert!(msg.contains("127.0.0.1:9999"));
        assert!(msg.contains("5 attempts"));
        assert!(msg.contains("test error"));
    }

    // ------------------------------------------------------------------
    // Coalesced callers receive the same outcome
    // ------------------------------------------------------------------

    #[tokio::test]
    async fn coalesced_callers_receive_success() {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_handle = tokio::spawn(async move {
            let (_stream1, _) = listener.accept().await.unwrap();
            let (_stream2, _) = listener.accept().await.unwrap();
        });

        let config = RetryConfig::default();
        let gate = Arc::new(PeerConnectGate::new());

        let gate1 = Arc::clone(&gate);
        let gate2 = Arc::clone(&gate);
        let config1 = config.clone();
        let config2 = config.clone();

        let h1 =
            tokio::spawn(async move { connect_with_retry(&config1, &gate1, None, addr).await });
        let h2 =
            tokio::spawn(async move { connect_with_retry(&config2, &gate2, None, addr).await });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();

        assert!(r1.is_ok(), "caller 1 should succeed");
        assert!(r2.is_ok(), "caller 2 should succeed");

        accept_handle.abort();
    }

    #[tokio::test]
    async fn coalesced_callers_receive_failure() {
        let addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();

        let config = RetryConfig {
            max_attempts: 2,
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(20),
            backoff_multiplier: 2.0,
            connect_timeout: Duration::from_millis(200),
        };
        let gate = Arc::new(PeerConnectGate::new());

        let gate1 = Arc::clone(&gate);
        let gate2 = Arc::clone(&gate);
        let config1 = config.clone();
        let config2 = config.clone();

        let h1 =
            tokio::spawn(async move { connect_with_retry(&config1, &gate1, None, addr).await });
        let h2 =
            tokio::spawn(async move { connect_with_retry(&config2, &gate2, None, addr).await });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();

        assert!(r1.is_err(), "caller 1 should fail");
        assert!(r2.is_err(), "caller 2 should fail");
        assert_eq!(
            r1.as_ref().unwrap_err().attempts,
            r2.as_ref().unwrap_err().attempts
        );
    }

    #[tokio::test]
    async fn no_retry_config_fails_immediately() {
        let addr: SocketAddr = "192.0.2.2:12346".parse().unwrap();
        let config = RetryConfig::no_retry(Duration::from_millis(100));
        let gate = PeerConnectGate::new();
        let result = connect_with_retry(&config, &gate, None, addr).await;
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().attempts, 1);
    }

    #[tokio::test]
    async fn concurrent_connect_coalescing_single_attempt() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::net::TcpListener;

        let accept_count = Arc::new(AtomicUsize::new(0));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count_clone = Arc::clone(&accept_count);

        let accept_handle = tokio::spawn(async move {
            loop {
                if let Ok((_stream, _)) = listener.accept().await {
                    accept_count_clone.fetch_add(1, Ordering::SeqCst);
                }
            }
        });

        let config = RetryConfig::default();
        let gate = Arc::new(PeerConnectGate::new());

        let gate1 = Arc::clone(&gate);
        let gate2 = Arc::clone(&gate);
        let config1 = config.clone();
        let config2 = config.clone();

        let h1 =
            tokio::spawn(async move { connect_with_retry(&config1, &gate1, None, addr).await });
        let h2 =
            tokio::spawn(async move { connect_with_retry(&config2, &gate2, None, addr).await });

        let r1 = h1.await.unwrap();
        let r2 = h2.await.unwrap();

        assert!(r1.is_ok());
        assert!(r2.is_ok());

        // Both callers get independent connections, so 2 accepts.
        let accepted = accept_count.load(Ordering::SeqCst);
        assert_eq!(accepted, 2, "two independent TCP connections");

        accept_handle.abort();
    }
}
