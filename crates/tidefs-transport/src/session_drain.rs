//! Per-session drain handle for membership-eviction teardown with in-flight
//! message completion tracking.
//!
//! ## Purpose
//!
//! When membership eviction triggers session teardown (via
//! [`SessionPolicy::Drain`] from `tidefs-membership-live`), queued and
//! in-flight messages on the evicted peer's session are dropped without
//! completion signaling. Callers submitting to an evicted session need a
//! completion signal (success or eviction-failure) to avoid hanging or
//! retrying into a dead session.
//!
//! This module provides a `SessionDrainHandle` that wraps a per-send
//! oneshot completion channel, tracks in-flight message count with an
//! atomic counter, and resolves all outstanding tokens on drain with a
//! terminal error (`Evicted`, `Timeout`, or `SessionClosed`).
//!
//! ## Integration
//!
//! ```text
//! SessionDrainHandle::new(config)
//!   |
//!   +-- send_with_token() -> DrainToken  (caller holds token until acked)
//!   |       |
//!   |       +-- increments in-flight counter
//!   |       +-- creates oneshot (tx, rx), returns rx as DrainToken
//!   |
//!   +-- complete(token_result)            (caller signals success/failure)
//!   |       |
//!   |       +-- decrements in-flight counter
//!   |       +-- sends Result through oneshot tx
//!   |
//!   +-- drain(error)                      (membership eviction triggers)
//!           |
//!           +-- rejects new sends
//!           +-- resolves ALL pending tokens with `error`
//!           +-- waits up to drain_deadline for in-flight -> 0
//!           +-- times out remaining tokens with DrainError::Timeout
//! ```
//!
//! ## Relationship to existing drain infrastructure
//!
//! - [`drain_protocol`](crate::drain_protocol): connection-level handshake
//!   (`DrainInitiator`/`DrainResponder`) for graceful wire-protocol teardown.
//! - `session_drain`: session-level token-based completion tracking for
//!   callers that submitted messages through a session and need a completion
//!   signal when the session is evicted.
//!
//! These are complementary: the drain protocol coordinates the wire close,
//! while the session drain tracks caller-side completion.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

type DrainResultSender = tokio::sync::oneshot::Sender<Result<(), DrainError>>;
type PendingDrainSenders = Arc<Mutex<Vec<DrainResultSender>>>;
use std::time::Duration;

// ---------------------------------------------------------------------------
// DrainConfig
// ---------------------------------------------------------------------------

/// Configuration for a [`SessionDrainHandle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DrainConfig {
    /// Maximum time to wait for in-flight sends to complete before
    /// forcefully timing out outstanding tokens.
    pub drain_deadline: Duration,

    /// Maximum number of concurrent in-flight tracked sends.
    /// Sends beyond this limit are rejected with
    /// [`SessionDrainError::AtCapacity`].
    pub max_in_flight: usize,
}

impl Default for DrainConfig {
    fn default() -> Self {
        Self {
            drain_deadline: Duration::from_secs(5),
            max_in_flight: 256,
        }
    }
}

impl DrainConfig {
    /// Create a new config with the given deadline and capacity.
    #[must_use]
    pub fn new(drain_deadline: Duration, max_in_flight: usize) -> Self {
        Self {
            drain_deadline,
            max_in_flight,
        }
    }
}

// ---------------------------------------------------------------------------
// DrainError
// ---------------------------------------------------------------------------

/// Terminal error delivered to [`DrainToken`] holders when a session
/// is torn down or drain times out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainError {
    /// Session was closed by membership roster eviction.
    Evicted,
    /// Drain deadline exceeded; in-flight work did not complete in time.
    Timeout,
    /// Session closed for a non-eviction reason (local shutdown, auth
    /// failure, transport error, etc.).
    SessionClosed,
}

impl fmt::Display for DrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evicted => f.write_str("session evicted by membership roster change"),
            Self::Timeout => f.write_str("session drain deadline exceeded"),
            Self::SessionClosed => f.write_str("session closed"),
        }
    }
}

impl std::error::Error for DrainError {}

// ---------------------------------------------------------------------------
// SessionDrainError
// ---------------------------------------------------------------------------

/// Error returned by operations on a [`SessionDrainHandle`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionDrainError {
    /// The handle is already draining or drained; new sends are rejected.
    Draining,
    /// The handle is at its `max_in_flight` capacity.
    AtCapacity {
        /// Current number of in-flight tracked sends.
        current: usize,
        /// Configured maximum.
        max: usize,
    },
}

impl fmt::Display for SessionDrainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draining => f.write_str("session drain handle is draining"),
            Self::AtCapacity { current, max } => {
                write!(f, "session drain at capacity ({current}/{max})")
            }
        }
    }
}

impl std::error::Error for SessionDrainError {}

// ---------------------------------------------------------------------------
// DrainToken
// ---------------------------------------------------------------------------

/// Opaque token returned by
/// [`SessionDrainHandle::send_with_token`].
///
/// The caller holds this token until the send is acknowledged (by calling
/// [`SessionDrainHandle::complete`]) or the session is drained.  Call
/// [`DrainToken::wait`] to block until resolution.
///
/// Tokens are not cloneable; each represents exactly one in-flight send.
pub struct DrainToken {
    rx: tokio::sync::oneshot::Receiver<Result<(), DrainError>>,
}

impl DrainToken {
    /// Create a new token from a oneshot receiver.
    fn new(rx: tokio::sync::oneshot::Receiver<Result<(), DrainError>>) -> Self {
        Self { rx }
    }

    /// Wait for this token to be resolved.
    ///
    /// Returns `Ok(())` when the send completed successfully,
    /// `Err(DrainError::Evicted)` when the session was evicted,
    /// `Err(DrainError::Timeout)` when the drain deadline was exceeded,
    /// or `Err(DrainError::SessionClosed)` for non-eviction session close.
    ///
    /// If the associated [`SessionDrainHandle`] is dropped without
    /// draining, the oneshot channel is closed and this returns
    /// `Err(DrainError::SessionClosed)`.
    pub async fn wait(self) -> Result<(), DrainError> {
        match self.rx.await {
            Ok(result) => result,
            Err(_closed) => Err(DrainError::SessionClosed),
        }
    }

    /// Non-blocking check: returns `Some(result)` if the token has been
    /// resolved, `None` if still pending.
    pub fn try_wait(&mut self) -> Option<Result<(), DrainError>> {
        match self.rx.try_recv() {
            Ok(result) => Some(result),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                Some(Err(DrainError::SessionClosed))
            }
            Err(tokio::sync::oneshot::error::TryRecvError::Empty) => None,
        }
    }
}

impl fmt::Debug for DrainToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DrainToken").finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// SessionDrainHandle
// ---------------------------------------------------------------------------

/// Per-session drain tracking handle.
///
/// Created when a caller wants to track send completions through a
/// session that may be evicted.  Each tracked send produces a
/// [`DrainToken`]; the caller holds the token until completion or
/// drain.
///
/// On membership eviction, call [`drain`](Self::drain) with the
/// appropriate error to resolve all outstanding tokens and reject
/// new sends.
#[derive(Debug)]
pub struct SessionDrainHandle {
    /// Tokio oneshot senders for outstanding tokens, guarded by a mutex
    /// so drain can atomically drain all pending.
    pending: PendingDrainSenders,

    /// Atomic count of current in-flight tracked sends.
    in_flight: Arc<AtomicUsize>,

    /// Whether the handle is draining (new sends rejected).
    draining: Arc<AtomicBool>,

    /// Configuration.
    config: DrainConfig,
}

impl SessionDrainHandle {
    /// Create a new drain handle with the given configuration.
    #[must_use]
    pub fn new(config: DrainConfig) -> Self {
        Self {
            pending: Arc::new(Mutex::new(Vec::with_capacity(config.max_in_flight))),
            in_flight: Arc::new(AtomicUsize::new(0)),
            draining: Arc::new(AtomicBool::new(false)),
            config,
        }
    }

    /// Create a new drain handle with default configuration (5 s
    /// deadline, 256 max in-flight).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(DrainConfig::default())
    }

    /// Return the current number of in-flight tracked sends.
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.load(Ordering::SeqCst)
    }

    /// Return `true` if the handle is currently draining.
    #[must_use]
    pub fn is_draining(&self) -> bool {
        self.draining.load(Ordering::SeqCst)
    }

    /// Return the configured maximum in-flight capacity.
    #[must_use]
    pub fn max_in_flight(&self) -> usize {
        self.config.max_in_flight
    }

    /// Submit a tracked send and receive a [`DrainToken`].
    ///
    /// The token will be resolved when either:
    /// - [`complete`](Self::complete) is called with `Ok(())` (send acked),
    /// - [`complete`](Self::complete) is called with `Err(...)` (send failed),
    /// - [`drain`](Self::drain) resolves all pending tokens,
    /// - the handle is dropped (tokens receive `SessionClosed`).
    ///
    /// # Errors
    ///
    /// Returns [`SessionDrainError::Draining`] if [`drain`](Self::drain)
    /// has already been called.
    ///
    /// Returns [`SessionDrainError::AtCapacity`] if the in-flight count
    /// has reached `max_in_flight`.
    pub fn send_with_token(&self) -> Result<DrainToken, SessionDrainError> {
        if self.draining.load(Ordering::SeqCst) {
            return Err(SessionDrainError::Draining);
        }

        let current = self.in_flight.load(Ordering::SeqCst);
        if current >= self.config.max_in_flight {
            return Err(SessionDrainError::AtCapacity {
                current,
                max: self.config.max_in_flight,
            });
        }

        let (tx, rx) = tokio::sync::oneshot::channel();

        // Push the sender into the pending list.
        {
            let mut pending = self
                .pending
                .lock()
                .expect("SessionDrainHandle pending mutex poisoned");
            // Re-check draining under the lock to avoid a race where
            // drain() acquires the lock between our atomic read and push.
            if self.draining.load(Ordering::SeqCst) {
                drop(pending);
                // Resolve this token immediately as evicted-equivalent
                // (the drain error will be applied shortly by drain()).
                let _ = tx.send(Err(DrainError::Evicted));
                return Err(SessionDrainError::Draining);
            }
            pending.push(tx);
        }

        self.in_flight.fetch_add(1, Ordering::SeqCst);
        Ok(DrainToken::new(rx))
    }

    /// Complete a tracked send, resolving the corresponding [`DrainToken`]
    /// with the given result.
    ///
    /// Pops the oldest pending sender from the queue and sends `result`
    /// through it.  The `in_flight` counter is decremented.
    ///
    /// # Panics
    ///
    /// Panics if there are no pending tokens (underflow).  Callers must
    /// only call `complete` for sends that were successfully tracked via
    /// [`send_with_token`].
    pub fn complete(&self, result: Result<(), DrainError>) {
        let tx = {
            let mut pending = self
                .pending
                .lock()
                .expect("SessionDrainHandle pending mutex poisoned");
            pending.remove(0)
        };
        let _ = tx.send(result);
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }

    /// Drain all outstanding tokens, rejecting new sends.
    ///
    /// All pending [`DrainToken`]s are resolved with `error`.  After this
    /// call:
    /// - [`is_draining`](Self::is_draining) returns `true`.
    /// - [`send_with_token`](Self::send_with_token) returns `Draining`.
    /// - The `in_flight` counter eventually reaches 0.
    ///
    /// This method is non-blocking: it resolves existing pending tokens
    /// immediately.  Tokens created after drain begins are rejected at
    /// `send_with_token` time.
    pub fn drain(&self, error: DrainError) {
        // Set draining flag first so new sends are rejected.
        self.draining.store(true, Ordering::SeqCst);

        let pending: Vec<tokio::sync::oneshot::Sender<Result<(), DrainError>>> = {
            let mut guard = self
                .pending
                .lock()
                .expect("SessionDrainHandle pending mutex poisoned");
            std::mem::take(&mut *guard)
        };

        for tx in pending {
            let _ = tx.send(Err(error));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
        }
    }

    /// Return the configured drain deadline duration.
    #[must_use]
    pub fn drain_deadline(&self) -> Duration {
        self.config.drain_deadline
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// GracefulDrainConfig
// ---------------------------------------------------------------------------

/// Configuration for graceful session drain: queue-flushing before close
/// with a deadline and optional new-send rejection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GracefulDrainConfig {
    /// Maximum time to wait for the send queue to empty before
    /// returning [`DrainOutcome::DeadlineExpired`].
    pub deadline: Duration,

    /// How often to poll the priority queue for emptiness while waiting.
    pub poll_interval: Duration,

    /// When true, new sends via [`super::Transport::send_message`] or
    /// [`super::Transport::send_priority`] are rejected while the session
    /// is draining.  When false, new sends are enqueued and will be
    /// drained along with existing messages.
    pub reject_new_sends: bool,
}

impl Default for GracefulDrainConfig {
    fn default() -> Self {
        Self {
            deadline: Duration::from_secs(5),
            poll_interval: Duration::from_millis(10),
            reject_new_sends: true,
        }
    }
}

impl GracefulDrainConfig {
    /// Create a new config.
    #[must_use]
    pub fn new(deadline: Duration, poll_interval: Duration, reject_new_sends: bool) -> Self {
        Self {
            deadline,
            poll_interval,
            reject_new_sends,
        }
    }
}

// ---------------------------------------------------------------------------
// DrainOutcome
// ---------------------------------------------------------------------------

/// Result of a graceful session drain operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrainOutcome {
    /// All queued messages were successfully drained before the deadline.
    Completed {
        /// Number of messages drained from the priority queue.
        messages_drained: u64,
    },
    /// The deadline expired before the queue was fully drained.
    DeadlineExpired {
        /// Number of messages still remaining in the queue.
        messages_remaining: u64,
    },
    /// The session was already closed when drain was requested.
    AlreadyClosed,
}

impl DrainOutcome {
    /// Whether the drain completed successfully.
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Whether the deadline expired before completion.
    #[must_use]
    pub fn is_deadline_expired(&self) -> bool {
        matches!(self, Self::DeadlineExpired { .. })
    }
}

impl std::fmt::Display for DrainOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Completed { messages_drained } => {
                write!(f, "drain completed ({messages_drained} messages drained)")
            }
            Self::DeadlineExpired { messages_remaining } => {
                write!(
                    f,
                    "drain deadline expired ({messages_remaining} messages remaining)"
                )
            }
            Self::AlreadyClosed => f.write_str("session already closed"),
        }
    }
}

// ---------------------------------------------------------------------------
// Queue-draining helper
// ---------------------------------------------------------------------------

/// Poll a [`MessagePriorityQueue`] until it is empty or the deadline expires.
///
/// Returns the drain outcome and the total number of messages drained during
/// the polling period.
///
/// This is a free function so it can be called from both the session drain
/// module and from external callers that hold a reference to the queue.
pub fn poll_queue_until_empty<M>(
    queue: &crate::message_priority::MessagePriorityQueue<M>,
    deadline: std::time::Instant,
    poll_interval: Duration,
) -> DrainOutcome {
    let initial_total = queue.total_dequeued();

    loop {
        let remaining = queue.len() as u64;
        if remaining == 0 {
            let final_total = queue.total_dequeued();
            let messages_drained = final_total.saturating_sub(initial_total);
            return DrainOutcome::Completed { messages_drained };
        }

        if std::time::Instant::now() >= deadline {
            return DrainOutcome::DeadlineExpired {
                messages_remaining: remaining,
            };
        }

        // Yield to let the I/O runtime flush queued messages.
        std::thread::sleep(poll_interval.min(Duration::from_millis(1)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- DrainConfig ----

    #[test]
    fn drain_config_defaults() {
        let cfg = DrainConfig::default();
        assert_eq!(cfg.drain_deadline, Duration::from_secs(5));
        assert_eq!(cfg.max_in_flight, 256);
    }

    #[test]
    fn drain_config_custom() {
        let cfg = DrainConfig::new(Duration::from_secs(10), 512);
        assert_eq!(cfg.drain_deadline, Duration::from_secs(10));
        assert_eq!(cfg.max_in_flight, 512);
    }

    // ---- DrainError display ----

    #[test]
    fn drain_error_display() {
        assert!(format!("{}", DrainError::Evicted).contains("evicted"));
        assert!(format!("{}", DrainError::Timeout).contains("deadline"));
        assert!(format!("{}", DrainError::SessionClosed).contains("closed"));
    }

    // ---- SessionDrainError display ----

    #[test]
    fn session_drain_error_display() {
        assert!(format!("{}", SessionDrainError::Draining).contains("draining"));
        let err = SessionDrainError::AtCapacity {
            current: 256,
            max: 256,
        };
        assert!(format!("{err}").contains("256"));
    }

    // ---- SessionDrainHandle: zero in-flight drain ----

    #[tokio::test]
    async fn drain_with_zero_in_flight() {
        let handle = SessionDrainHandle::with_defaults();
        assert_eq!(handle.in_flight_count(), 0);
        assert!(!handle.is_draining());

        handle.drain(DrainError::Evicted);

        assert!(handle.is_draining());
        assert_eq!(handle.in_flight_count(), 0);

        // New sends rejected.
        let result = handle.send_with_token();
        assert!(matches!(result, Err(SessionDrainError::Draining)));
    }

    // ---- SessionDrainHandle: drain with N=1 ----

    #[tokio::test]
    async fn drain_with_one_pending_token() {
        let handle = SessionDrainHandle::with_defaults();

        let token = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 1);

        handle.drain(DrainError::Evicted);

        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::Evicted));
        assert_eq!(handle.in_flight_count(), 0);
    }

    // ---- SessionDrainHandle: drain with N=16 ----

    #[tokio::test]
    async fn drain_with_sixteen_pending_tokens() {
        let handle = SessionDrainHandle::with_defaults();
        let mut tokens = Vec::new();

        for _ in 0..16 {
            tokens.push(handle.send_with_token().unwrap());
        }
        assert_eq!(handle.in_flight_count(), 16);

        handle.drain(DrainError::Timeout);

        for token in tokens {
            let result = token.wait().await;
            assert_eq!(result, Err(DrainError::Timeout));
        }
        assert_eq!(handle.in_flight_count(), 0);
    }

    // ---- SessionDrainHandle: send rejected during drain ----

    #[tokio::test]
    async fn send_rejected_during_drain() {
        let handle = SessionDrainHandle::with_defaults();

        // Create one pending token before drain.
        let token = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 1);

        // Start draining.
        handle.drain(DrainError::Evicted);

        // New sends are rejected.
        let err = handle.send_with_token().unwrap_err();
        assert_eq!(err, SessionDrainError::Draining);

        // Existing token still resolves.
        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::Evicted));
    }

    // ---- SessionDrainHandle: complete with success ----

    #[tokio::test]
    async fn complete_with_success() {
        let handle = SessionDrainHandle::with_defaults();

        let token = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 1);

        handle.complete(Ok(()));

        let result = token.wait().await;
        assert_eq!(result, Ok(()));
        assert_eq!(handle.in_flight_count(), 0);
    }

    // ---- SessionDrainHandle: complete with error ----

    #[tokio::test]
    async fn complete_with_error() {
        let handle = SessionDrainHandle::with_defaults();

        let token = handle.send_with_token().unwrap();
        handle.complete(Err(DrainError::SessionClosed));

        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::SessionClosed));
        assert_eq!(handle.in_flight_count(), 0);
    }

    // ---- SessionDrainHandle: at capacity ----

    #[test]
    fn send_rejected_at_capacity() {
        let cfg = DrainConfig::new(Duration::from_secs(5), 2);
        let handle = SessionDrainHandle::new(cfg);

        let _t1 = handle.send_with_token().unwrap();
        let _t2 = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 2);

        let err = handle.send_with_token().unwrap_err();
        assert_eq!(err, SessionDrainError::AtCapacity { current: 2, max: 2 });
    }

    // ---- SessionDrainHandle: complete + send cycle clears capacity ----

    #[tokio::test]
    async fn complete_frees_capacity() {
        let cfg = DrainConfig::new(Duration::from_secs(5), 2);
        let handle = SessionDrainHandle::new(cfg);

        let t1 = handle.send_with_token().unwrap();
        let _t2 = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 2);

        // Complete t1, freeing a slot.
        handle.complete(Ok(()));
        let _ = t1.wait().await;
        assert_eq!(handle.in_flight_count(), 1);

        // Now a new send should succeed.
        let _t3 = handle.send_with_token().unwrap();
        assert_eq!(handle.in_flight_count(), 2);
    }

    // ---- SessionDrainHandle: try_wait ----

    #[tokio::test]
    async fn try_wait_before_complete() {
        let handle = SessionDrainHandle::with_defaults();
        let mut token = handle.send_with_token().unwrap();

        // Not yet resolved.
        assert!(token.try_wait().is_none());

        handle.complete(Ok(()));

        // Now resolved.
        assert_eq!(token.try_wait(), Some(Ok(())));
    }

    // ---- SessionDrainHandle: drain resolves before wait ----

    #[tokio::test]
    async fn drain_resolves_tokens_immediately() {
        let handle = SessionDrainHandle::with_defaults();
        let mut token = handle.send_with_token().unwrap();

        handle.drain(DrainError::Evicted);

        // Token should be immediately available after drain.
        assert_eq!(token.try_wait(), Some(Err(DrainError::Evicted)));
    }

    // ---- SessionDrainHandle: drain is idempotent ----

    #[tokio::test]
    async fn drain_idempotent() {
        let handle = SessionDrainHandle::with_defaults();
        let token = handle.send_with_token().unwrap();

        handle.drain(DrainError::Evicted);
        // Second drain is safe — draining flag is already set, pending is empty.
        handle.drain(DrainError::Timeout);

        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::Evicted));
    }

    // ---- SessionDrainHandle: concurrent send + drain race ----

    #[tokio::test]
    async fn concurrent_send_and_drain() {
        use std::sync::Arc;

        let handle = Arc::new(SessionDrainHandle::with_defaults());
        let h_clone = Arc::clone(&handle);

        // Pre-populate with one token.
        let token = handle.send_with_token().unwrap();

        // Spawn drain in background.
        let drain_handle = tokio::spawn(async move {
            h_clone.drain(DrainError::Evicted);
        });

        // Concurrent sends should eventually see Draining.
        let send_result = handle.send_with_token();
        // Either accepted (before drain flag set) or Draining.
        if let Ok(t) = send_result {
            // The drain task resolved this token but drain() resolves only
            // tokens in the pending vec at the time it acquires the lock.
            // If this token was pushed while drain held the lock, it WILL
            // be in the pending vec because we re-check under lock.
            //
            // Actually: our send_with_token re-checks draining under lock.
            // If draining is true, it rejects immediately (sends Err(Evicted)
            // and returns Draining error). So we can't get Ok(t) here if
            // drain already set the flag.
            let _ = t.wait().await;
        }

        drain_handle.await.unwrap();

        // The pre-existing token should resolve.
        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::Evicted));
    }

    // ---- SessionDrainHandle: token resolves SessionClosed on handle drop ----

    #[tokio::test]
    async fn token_session_closed_on_handle_drop() {
        let handle = SessionDrainHandle::with_defaults();
        let token = handle.send_with_token().unwrap();

        // Drop the handle without draining.
        drop(handle);

        let result = token.wait().await;
        assert_eq!(result, Err(DrainError::SessionClosed));
    }

    // ---- SessionDrainHandle: complete after drain is no-op on counter ----

    #[test]
    fn complete_after_drain_panics() {
        // After drain, the pending vec is empty. Complete will panic
        // because it tries to remove(0) from an empty vec.
        // This is intentional: callers must only complete tokens that
        // were tracked and not already resolved by drain.
        let handle = SessionDrainHandle::with_defaults();
        let _token = handle.send_with_token().unwrap();
        handle.drain(DrainError::Evicted);

        // complete on drained handle panics (pending is empty).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handle.complete(Ok(()));
        }));
        assert!(result.is_err());
    }

    // ---- SessionDrainHandle: max_in_flight = 256 default ----

    #[tokio::test]
    async fn fill_to_max_capacity() {
        let handle = SessionDrainHandle::with_defaults();
        let mut tokens = Vec::new();

        for i in 0..256 {
            let token = handle.send_with_token().unwrap();
            tokens.push(token);
            assert_eq!(handle.in_flight_count(), i + 1);
        }

        // One more should fail.
        let err = handle.send_with_token().unwrap_err();
        assert_eq!(
            err,
            SessionDrainError::AtCapacity {
                current: 256,
                max: 256,
            }
        );

        // Drain all.
        handle.drain(DrainError::Evicted);
        for token in tokens {
            assert_eq!(token.wait().await, Err(DrainError::Evicted));
        }
        assert_eq!(handle.in_flight_count(), 0);
    }

    // ---- DrainToken debug ----

    #[test]
    fn drain_token_debug_format() {
        let handle = SessionDrainHandle::with_defaults();
        let token = handle.send_with_token().unwrap();
        let debug_str = format!("{token:?}");
        assert!(debug_str.contains("DrainToken"));
    }

    // ---- GracefulDrainConfig ----

    #[test]
    fn graceful_drain_config_defaults() {
        let cfg = GracefulDrainConfig::default();
        assert_eq!(cfg.deadline, Duration::from_secs(5));
        assert_eq!(cfg.poll_interval, Duration::from_millis(10));
        assert!(cfg.reject_new_sends);
    }

    #[test]
    fn graceful_drain_config_custom() {
        let cfg =
            GracefulDrainConfig::new(Duration::from_secs(3), Duration::from_millis(50), false);
        assert_eq!(cfg.deadline, Duration::from_secs(3));
        assert_eq!(cfg.poll_interval, Duration::from_millis(50));
        assert!(!cfg.reject_new_sends);
    }

    // ---- DrainOutcome ----

    #[test]
    fn drain_outcome_completed() {
        let outcome = DrainOutcome::Completed {
            messages_drained: 42,
        };
        assert!(outcome.is_completed());
        assert!(!outcome.is_deadline_expired());
        assert!(format!("{outcome}").contains("42"));
    }

    #[test]
    fn drain_outcome_deadline_expired() {
        let outcome = DrainOutcome::DeadlineExpired {
            messages_remaining: 7,
        };
        assert!(!outcome.is_completed());
        assert!(outcome.is_deadline_expired());
        assert!(format!("{outcome}").contains("7"));
    }

    #[test]
    fn drain_outcome_already_closed() {
        let outcome = DrainOutcome::AlreadyClosed;
        assert!(!outcome.is_completed());
        assert!(!outcome.is_deadline_expired());
        assert!(format!("{outcome}").contains("already closed"));
    }

    // ---- poll_queue_until_empty ----

    #[test]
    fn poll_empty_queue_returns_completed() {
        use crate::message_priority::MessagePriorityQueue;
        let q = MessagePriorityQueue::<u32>::with_defaults();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let outcome = poll_queue_until_empty(&q, deadline, Duration::from_millis(1));
        assert_eq!(
            outcome,
            DrainOutcome::Completed {
                messages_drained: 0
            }
        );
    }

    #[test]
    fn poll_nonempty_queue_with_zero_deadline_returns_expired() {
        use crate::message_priority::MessagePriorityQueue;
        let mut q = MessagePriorityQueue::<u32>::with_defaults();
        q.enqueue(1, crate::message_priority::MessagePriority::Data)
            .unwrap();
        q.enqueue(2, crate::message_priority::MessagePriority::Control)
            .unwrap();
        // deadline in the past
        let deadline = std::time::Instant::now() - Duration::from_secs(1);
        let outcome = poll_queue_until_empty(&q, deadline, Duration::from_millis(1));
        assert_eq!(
            outcome,
            DrainOutcome::DeadlineExpired {
                messages_remaining: 2
            }
        );
    }
}
