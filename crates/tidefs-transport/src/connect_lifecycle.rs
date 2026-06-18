// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-session connection-establishment timeout and lifecycle state signaling.
//!
//! ## Purpose
//!
//! Transport sessions transition through three high-level lifecycle states:
//!
//! - **Connecting** — the session is in the process of establishing a
//!   connection (TCP handshake, Hello/HelloAck, session establishment,
//!   and cohort attachment).  This is the initial state for every session.
//! - **Ready** — the session is established and can carry messages.
//! - **Dead** — the session has reached a terminal state (closed, timeout
//!   exhausted, or permanent failure).
//!
//! Callers observe lifecycle transitions through a configurable callback
//! and a synchronous query method.  A connect timeout bounds the
//! `Connecting` phase: if the underlying handshake does not complete
//! within the configured timeout, the session is forced to `Dead` with
//! a timeout error.
//!
//! ## Relationship to other components
//!
//! - **`SessionState`** ([`crate::session::SessionState`]): the low-level
//!   fine-grained state machine.  `SessionLifecycle` maps ranges of
//!   `SessionState` variants to the three high-level phases.
//! - **`SessionReconnector`** ([`crate::session_reconnector`]): handles
//!   reconnection for already-established sessions.  The connect lifecycle
//!   covers the *initial* establishment; reconnection is managed separately.
//! - **Unreachability** ([`crate::unreachable_peer`]): a `Dead` lifecycle
//!   transition can feed into the unreachability escalation path.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// ConnectConfig
// ---------------------------------------------------------------------------

/// Configuration for per-session connection-establishment timeout.
///
/// When `connect_timeout` is `Some(d)`, the session establishment handshake
/// must complete within `d`.  If the timeout fires, the session transitions
/// to [`SessionLifecycle::Dead`] with a [`ConnectTimeoutError`].
///
/// When `connect_timeout` is `None`, the session may wait indefinitely
/// during connection establishment (the pre-existing behaviour).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectConfig {
    /// Maximum time allowed for the initial connection handshake to
    /// complete.  `None` disables the timeout (indefinite wait).
    pub connect_timeout: Option<Duration>,
}

impl ConnectConfig {
    /// Create a new `ConnectConfig` with the given timeout.
    #[must_use]
    pub fn new(connect_timeout: Option<Duration>) -> Self {
        Self { connect_timeout }
    }

    /// Create a `ConnectConfig` with no timeout (indefinite wait).
    #[must_use]
    pub fn no_timeout() -> Self {
        Self {
            connect_timeout: None,
        }
    }

    /// Create a `ConnectConfig` with the given timeout duration.
    #[must_use]
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            connect_timeout: Some(timeout),
        }
    }

    /// Returns `true` if a connect timeout is configured.
    #[must_use]
    pub fn has_timeout(&self) -> bool {
        self.connect_timeout.is_some()
    }
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Some(Duration::from_secs(30)),
        }
    }
}

// ---------------------------------------------------------------------------
// SessionLifecycle
// ---------------------------------------------------------------------------

/// High-level lifecycle phase of a transport session.
///
/// This is a caller-facing view that maps the fine-grained
/// [`crate::session::SessionState`] machine onto three observable phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionLifecycle {
    /// The session is in the process of connecting.
    ///
    /// Covers `Unconnected`, `Connecting`, `Handshaking`, `Bound`,
    /// `CohortAttached`, `Reconnecting`, and `ResumePending` states.
    Connecting,
    /// The session is established and can carry messages.
    ///
    /// Covers `Established` and `Degraded` states (where the session
    /// is still usable).
    Ready,
    /// The session has reached a terminal state.
    ///
    /// Covers `Closed` and any timeout-forced death.
    Dead,
}

impl SessionLifecycle {
    /// Return a human-readable label for this lifecycle phase.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Ready => "ready",
            Self::Dead => "dead",
        }
    }

    /// Returns `true` if the session is in the `Ready` phase and can
    /// carry messages.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Returns `true` if the session has reached a terminal state.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }
}

impl fmt::Display for SessionLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ConnectTimeoutError
// ---------------------------------------------------------------------------

/// Error returned when a session's connection-establishment timeout fires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectTimeoutError {
    /// The configured timeout duration that was exceeded.
    pub timeout: Duration,
    /// The peer node identifier of the session that timed out.
    pub peer_node: u64,
    /// When the connect attempt started.
    pub started_at: Instant,
    /// When the timeout was detected.
    pub timed_out_at: Instant,
}

/// Timeout enforcement was attempted from a lifecycle state where it is invalid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectTimeoutStateError;

impl fmt::Display for ConnectTimeoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "connect to peer {} timed out after {:?}",
            self.peer_node, self.timeout
        )
    }
}

impl std::error::Error for ConnectTimeoutError {}

// ---------------------------------------------------------------------------
// LifecycleChangeCallback
// ---------------------------------------------------------------------------

/// Callback trait invoked when a session's [`SessionLifecycle`] transitions.
///
/// Implementors can register with
/// [`ConnectLifecycle::on_lifecycle_change`] to react to state transitions
/// without polling.
pub trait LifecycleChangeCallback: Send + Sync {
    /// Called when a session transitions to a new lifecycle phase.
    ///
    /// * `session_id` — the session identifier.
    /// * `peer_node` — the remote peer's node identifier.
    /// * `old_lifecycle` — the previous lifecycle phase.
    /// * `new_lifecycle` — the new lifecycle phase.
    fn on_lifecycle_change(
        &self,
        session_id: u64,
        peer_node: u64,
        old_lifecycle: SessionLifecycle,
        new_lifecycle: SessionLifecycle,
    );
}

/// Type-erased callback reference for lifecycle change notifications.
pub type LifecycleChangeCallbackRef = Arc<dyn LifecycleChangeCallback>;

// ---------------------------------------------------------------------------
// ConnectLifecycle
// ---------------------------------------------------------------------------

/// Tracks the connection-establishment timeout and lifecycle state for a
/// single transport session.
///
/// Created when a session begins connecting.  Callers invoke
/// [`check_timeout`](Self::check_timeout) periodically (e.g., from a
/// background task or the session tick) to detect elapsed timeouts, and
/// [`transition`](Self::transition) when the underlying `SessionState`
/// changes.
///
/// # Example
///
/// ```ignore
/// use tidefs_transport::connect_lifecycle::{
///     ConnectConfig, ConnectLifecycle, SessionLifecycle,
/// };
///
/// let config = ConnectConfig::with_timeout(Duration::from_secs(10));
/// let mut lifecycle = ConnectLifecycle::new(42, 7, Instant::now(), config);
///
/// // ... during session establishment ...
/// if lifecycle.check_timeout(Instant::now()) {
///     // timeout fired — tear down session
/// }
///
/// // On successful establishment:
/// lifecycle.transition(SessionLifecycle::Ready, Instant::now());
/// assert!(lifecycle.current().is_ready());
/// ```
pub struct ConnectLifecycle {
    /// The session identifier.
    session_id: u64,
    /// The remote peer's node identifier.
    peer_node: u64,
    /// Current lifecycle phase.
    current: SessionLifecycle,
    /// When the connect attempt started (for timeout calculation).
    started_at: Instant,
    /// Connection-establishment configuration.
    config: ConnectConfig,
    /// Optional callback for lifecycle transitions.
    on_change: Option<LifecycleChangeCallbackRef>,
}

impl ConnectLifecycle {
    /// Create a new `ConnectLifecycle` tracker for a session that is
    /// beginning connection establishment.
    #[must_use]
    pub fn new(
        session_id: u64,
        peer_node: u64,
        started_at: Instant,
        config: ConnectConfig,
    ) -> Self {
        Self {
            session_id,
            peer_node,
            current: SessionLifecycle::Connecting,
            started_at,
            config,
            on_change: None,
        }
    }

    /// Attach a callback to be invoked on every lifecycle transition.
    #[must_use]
    pub fn with_lifecycle_callback(mut self, cb: LifecycleChangeCallbackRef) -> Self {
        self.on_change = Some(cb);
        self
    }

    /// Set or replace the lifecycle change callback.
    pub fn set_lifecycle_callback(&mut self, cb: LifecycleChangeCallbackRef) {
        self.on_change = Some(cb);
    }

    /// Remove the lifecycle change callback.
    pub fn clear_lifecycle_callback(&mut self) {
        self.on_change = None;
    }

    /// Return the current lifecycle phase.
    #[must_use]
    pub fn current(&self) -> SessionLifecycle {
        self.current
    }

    /// Return the configured connect timeout, if any.
    #[must_use]
    pub fn connect_timeout(&self) -> Option<Duration> {
        self.config.connect_timeout
    }

    /// Return the session identifier.
    #[must_use]
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Return the peer node identifier.
    #[must_use]
    pub fn peer_node(&self) -> u64 {
        self.peer_node
    }

    /// Return when the connect attempt started.
    #[must_use]
    pub fn started_at(&self) -> Instant {
        self.started_at
    }

    /// Check whether the connect timeout has elapsed.
    ///
    /// Returns `true` if the session is still `Connecting` and the
    /// configured timeout (if any) has elapsed since `started_at`.
    /// The caller is responsible for transitioning the session to
    /// `Dead` after a `true` return.
    ///
    /// This is a pure query; it does **not** mutate state.  Call
    /// [`transition_to_dead`](Self::transition_to_dead) to perform
    /// the actual state transition after a timeout.
    #[must_use]
    pub fn check_timeout(&self, now: Instant) -> bool {
        if self.current != SessionLifecycle::Connecting {
            return false;
        }
        match self.config.connect_timeout {
            Some(timeout) => now.duration_since(self.started_at) >= timeout,
            None => false,
        }
    }

    /// Transition to a new lifecycle phase.
    ///
    /// Returns the previous phase for caller inspection.  If the transition
    /// is to `Dead`, the reason can be inspected via
    /// [`ConnectLifecycle::current`].
    ///
    /// Does nothing (returns `Err(previous)`) if already in the target state
    /// or if already `Dead`.
    pub fn transition(
        &mut self,
        new: SessionLifecycle,
        now: Instant,
    ) -> Result<SessionLifecycle, SessionLifecycle> {
        let old = self.current;
        if old == new || old == SessionLifecycle::Dead {
            return Err(old);
        }
        self.current = new;
        if let Some(ref cb) = self.on_change {
            cb.on_lifecycle_change(self.session_id, self.peer_node, old, new);
        }
        let _ = now;
        Ok(old)
    }

    /// Transition to `Dead` due to a connect timeout.
    ///
    /// Returns the timeout error if the session was `Connecting` and the
    /// timeout has elapsed.  Returns `Ok(None)` if already dead.  Returns
    /// `Err(ConnectTimeoutStateError)` if the session is already `Ready` (timeout enforcement
    /// should not fire after a successful connection).
    pub fn transition_to_dead_on_timeout(
        &mut self,
        now: Instant,
    ) -> Result<Option<ConnectTimeoutError>, ConnectTimeoutStateError> {
        if self.current == SessionLifecycle::Dead {
            return Ok(None);
        }
        if self.current != SessionLifecycle::Connecting {
            // Already in Ready — timeout should not fire.
            return Err(ConnectTimeoutStateError);
        }
        match self.config.connect_timeout {
            Some(timeout) if now.duration_since(self.started_at) >= timeout => {
                let err = ConnectTimeoutError {
                    timeout,
                    peer_node: self.peer_node,
                    started_at: self.started_at,
                    timed_out_at: now,
                };
                let old = self.current;
                self.current = SessionLifecycle::Dead;
                if let Some(ref cb) = self.on_change {
                    cb.on_lifecycle_change(
                        self.session_id,
                        self.peer_node,
                        old,
                        SessionLifecycle::Dead,
                    );
                }
                Ok(Some(err))
            }
            _ => {
                // Timeout not yet elapsed or not configured.
                // Caller should use check_timeout first.
                Ok(None)
            }
        }
    }

    /// Reset the connect start time (e.g., on reconnection attempt).
    pub fn reset_connect_start(&mut self, started_at: Instant) {
        self.started_at = started_at;
    }

    /// Force the lifecycle to `Dead` regardless of the current phase.
    ///
    /// This is appropriate for permanent failures that are not timeout
    /// related (e.g., peer removed from roster, auth failure).
    pub fn force_dead(&mut self) {
        if self.current == SessionLifecycle::Dead {
            return;
        }
        let old = self.current;
        self.current = SessionLifecycle::Dead;
        if let Some(ref cb) = self.on_change {
            cb.on_lifecycle_change(self.session_id, self.peer_node, old, SessionLifecycle::Dead);
        }
    }
}

impl fmt::Debug for ConnectLifecycle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectLifecycle")
            .field("session_id", &self.session_id)
            .field("peer_node", &self.peer_node)
            .field("current", &self.current)
            .field("started_at", &self.started_at)
            .field("connect_timeout", &self.config.connect_timeout)
            .field("has_callback", &self.on_change.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // ---- Helper: recording callback ----

    struct RecordingCallback {
        events: Mutex<Vec<(u64, u64, SessionLifecycle, SessionLifecycle)>>,
    }

    impl RecordingCallback {
        fn new() -> Self {
            Self {
                events: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<(u64, u64, SessionLifecycle, SessionLifecycle)> {
            self.events.lock().unwrap().clone()
        }
    }

    impl LifecycleChangeCallback for RecordingCallback {
        fn on_lifecycle_change(
            &self,
            session_id: u64,
            peer_node: u64,
            old: SessionLifecycle,
            new: SessionLifecycle,
        ) {
            self.events
                .lock()
                .unwrap()
                .push((session_id, peer_node, old, new));
        }
    }

    fn now() -> Instant {
        Instant::now()
    }

    // ---- ConnectConfig ----

    #[test]
    fn connect_config_default_has_timeout() {
        let cfg = ConnectConfig::default();
        assert!(cfg.has_timeout());
        assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(30)));
    }

    #[test]
    fn connect_config_no_timeout() {
        let cfg = ConnectConfig::no_timeout();
        assert!(!cfg.has_timeout());
        assert_eq!(cfg.connect_timeout, None);
    }

    #[test]
    fn connect_config_with_timeout() {
        let cfg = ConnectConfig::with_timeout(Duration::from_secs(5));
        assert!(cfg.has_timeout());
        assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(5)));
    }

    // ---- SessionLifecycle ----

    #[test]
    fn lifecycle_as_str() {
        assert_eq!(SessionLifecycle::Connecting.as_str(), "connecting");
        assert_eq!(SessionLifecycle::Ready.as_str(), "ready");
        assert_eq!(SessionLifecycle::Dead.as_str(), "dead");
    }

    #[test]
    fn lifecycle_display() {
        assert_eq!(format!("{}", SessionLifecycle::Connecting), "connecting");
        assert_eq!(format!("{}", SessionLifecycle::Ready), "ready");
        assert_eq!(format!("{}", SessionLifecycle::Dead), "dead");
    }

    #[test]
    fn lifecycle_is_ready() {
        assert!(!SessionLifecycle::Connecting.is_ready());
        assert!(SessionLifecycle::Ready.is_ready());
        assert!(!SessionLifecycle::Dead.is_ready());
    }

    #[test]
    fn lifecycle_is_dead() {
        assert!(!SessionLifecycle::Connecting.is_dead());
        assert!(!SessionLifecycle::Ready.is_dead());
        assert!(SessionLifecycle::Dead.is_dead());
    }

    // ---- ConnectLifecycle basics ----

    #[test]
    fn new_starts_in_connecting() {
        let lc = ConnectLifecycle::new(1, 10, now(), ConnectConfig::default());
        assert_eq!(lc.current(), SessionLifecycle::Connecting);
    }

    #[test]
    fn new_stores_metadata() {
        let start = now();
        let lc = ConnectLifecycle::new(42, 7, start, ConnectConfig::default());
        assert_eq!(lc.session_id(), 42);
        assert_eq!(lc.peer_node(), 7);
        assert_eq!(lc.started_at(), start);
    }

    // ---- Timeout detection ----

    #[test]
    fn check_timeout_false_when_not_yet_elapsed() {
        let start = now();
        let lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(10)),
        );
        let just_after_start = start + Duration::from_millis(500);
        assert!(!lc.check_timeout(just_after_start));
    }

    #[test]
    fn check_timeout_true_when_elapsed() {
        let start = now();
        let lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(1)),
        );
        let after_timeout = start + Duration::from_secs(2);
        assert!(lc.check_timeout(after_timeout));
    }

    #[test]
    fn check_timeout_exact_boundary() {
        let start = now();
        let timeout = Duration::from_secs(1);
        let lc = ConnectLifecycle::new(1, 2, start, ConnectConfig::with_timeout(timeout));
        // Exactly at timeout boundary should return true
        assert!(lc.check_timeout(start + timeout));
    }

    #[test]
    fn check_timeout_false_with_no_timeout() {
        let start = now();
        let lc = ConnectLifecycle::new(1, 2, start, ConnectConfig::no_timeout());
        let far_future = start + Duration::from_secs(3600);
        assert!(!lc.check_timeout(far_future));
    }

    #[test]
    fn check_timeout_false_when_already_ready() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(1)),
        );
        lc.transition(SessionLifecycle::Ready, start).unwrap();
        let after_timeout = start + Duration::from_secs(2);
        assert!(!lc.check_timeout(after_timeout));
    }

    #[test]
    fn check_timeout_false_when_dead() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(1)),
        );
        lc.transition_to_dead_on_timeout(start + Duration::from_secs(2))
            .unwrap();
        let later = start + Duration::from_secs(10);
        assert!(!lc.check_timeout(later));
    }

    // ---- Lifecycle transitions ----

    #[test]
    fn transition_connecting_to_ready() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        let old = lc.transition(SessionLifecycle::Ready, now()).unwrap();
        assert_eq!(old, SessionLifecycle::Connecting);
        assert_eq!(lc.current(), SessionLifecycle::Ready);
    }

    #[test]
    fn transition_ready_to_dead() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.transition(SessionLifecycle::Ready, now()).unwrap();
        let old = lc.transition(SessionLifecycle::Dead, now()).unwrap();
        assert_eq!(old, SessionLifecycle::Ready);
        assert_eq!(lc.current(), SessionLifecycle::Dead);
    }

    #[test]
    fn transition_noop_same_state() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        let err = lc
            .transition(SessionLifecycle::Connecting, now())
            .unwrap_err();
        assert_eq!(err, SessionLifecycle::Connecting);
    }

    #[test]
    fn transition_noop_from_dead() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.force_dead();
        let err = lc.transition(SessionLifecycle::Ready, now()).unwrap_err();
        assert_eq!(err, SessionLifecycle::Dead);
    }

    // ---- Connect timeout transition ----

    #[test]
    fn transition_to_dead_on_timeout_fires() {
        let start = now();
        let timeout = Duration::from_secs(5);
        let mut lc = ConnectLifecycle::new(1, 2, start, ConnectConfig::with_timeout(timeout));
        let result = lc
            .transition_to_dead_on_timeout(start + Duration::from_secs(6))
            .unwrap();
        assert!(result.is_some());
        let err = result.unwrap();
        assert_eq!(err.timeout, timeout);
        assert_eq!(err.peer_node, 2);
        assert_eq!(err.started_at, start);
        assert_eq!(lc.current(), SessionLifecycle::Dead);
    }

    #[test]
    fn transition_to_dead_on_timeout_not_yet_elapsed() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(10)),
        );
        let result = lc
            .transition_to_dead_on_timeout(start + Duration::from_secs(2))
            .unwrap();
        assert!(result.is_none());
        assert_eq!(lc.current(), SessionLifecycle::Connecting);
    }

    #[test]
    fn transition_to_dead_on_timeout_no_timeout_configured() {
        let start = now();
        let mut lc = ConnectLifecycle::new(1, 2, start, ConnectConfig::no_timeout());
        let result = lc
            .transition_to_dead_on_timeout(start + Duration::from_secs(100))
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn transition_to_dead_on_timeout_already_ready_is_error() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(5)),
        );
        lc.transition(SessionLifecycle::Ready, start).unwrap();
        let result = lc.transition_to_dead_on_timeout(start + Duration::from_secs(10));
        assert!(result.is_err());
    }

    #[test]
    fn transition_to_dead_on_timeout_already_dead_returns_none() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(5)),
        );
        lc.force_dead();
        let result = lc
            .transition_to_dead_on_timeout(start + Duration::from_secs(10))
            .unwrap();
        assert!(result.is_none());
    }

    // ---- Force dead ----

    #[test]
    fn force_dead_from_connecting() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.force_dead();
        assert_eq!(lc.current(), SessionLifecycle::Dead);
    }

    #[test]
    fn force_dead_from_ready() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.transition(SessionLifecycle::Ready, now()).unwrap();
        lc.force_dead();
        assert_eq!(lc.current(), SessionLifecycle::Dead);
    }

    #[test]
    fn force_dead_idempotent() {
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.force_dead();
        lc.force_dead(); // no panic
        assert_eq!(lc.current(), SessionLifecycle::Dead);
    }

    // ---- Callback ----

    #[test]
    fn callback_invoked_on_transition() {
        let cb = Arc::new(RecordingCallback::new());
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default())
            .with_lifecycle_callback(cb.clone());
        lc.transition(SessionLifecycle::Ready, now()).unwrap();

        let events = cb.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            (1, 2, SessionLifecycle::Connecting, SessionLifecycle::Ready)
        );
    }

    #[test]
    fn callback_invoked_on_timeout_death() {
        let cb = Arc::new(RecordingCallback::new());
        let start = now();
        let mut lc = ConnectLifecycle::new(
            5,
            99,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(1)),
        )
        .with_lifecycle_callback(cb.clone());
        lc.transition_to_dead_on_timeout(start + Duration::from_secs(2))
            .unwrap();

        let events = cb.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            (5, 99, SessionLifecycle::Connecting, SessionLifecycle::Dead)
        );
    }

    #[test]
    fn callback_invoked_on_force_dead() {
        let cb = Arc::new(RecordingCallback::new());
        let mut lc = ConnectLifecycle::new(3, 7, now(), ConnectConfig::default())
            .with_lifecycle_callback(cb.clone());
        lc.force_dead();

        let events = cb.events();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0],
            (3, 7, SessionLifecycle::Connecting, SessionLifecycle::Dead)
        );
    }

    #[test]
    fn callback_not_invoked_on_noop_transition() {
        let cb = Arc::new(RecordingCallback::new());
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default())
            .with_lifecycle_callback(cb.clone());
        let _ = lc.transition(SessionLifecycle::Connecting, now());
        assert!(cb.events().is_empty());
    }

    #[test]
    fn set_and_clear_callback() {
        let cb1 = Arc::new(RecordingCallback::new());
        let cb2 = Arc::new(RecordingCallback::new());
        let mut lc = ConnectLifecycle::new(1, 2, now(), ConnectConfig::default());
        lc.set_lifecycle_callback(cb1.clone());
        lc.transition(SessionLifecycle::Ready, now()).unwrap();
        assert_eq!(cb1.events().len(), 1);
        assert!(cb2.events().is_empty());

        lc.set_lifecycle_callback(cb2.clone());
        lc.transition(SessionLifecycle::Dead, now()).unwrap();
        assert_eq!(cb1.events().len(), 1); // cb1 not called again
        assert_eq!(cb2.events().len(), 1);

        lc.clear_lifecycle_callback();
        // No crash, but can't transition from Dead anyway — still, no panic
    }

    // ---- Reset connect start ----

    #[test]
    fn reset_connect_start_updates_started_at() {
        let start = now();
        let mut lc = ConnectLifecycle::new(
            1,
            2,
            start,
            ConnectConfig::with_timeout(Duration::from_secs(5)),
        );
        let new_start = start + Duration::from_secs(10);
        lc.reset_connect_start(new_start);
        assert_eq!(lc.started_at(), new_start);
        // Timeout check should use new start
        assert!(!lc.check_timeout(new_start + Duration::from_secs(1)));
    }

    // ---- ConnectTimeoutError ----

    #[test]
    fn connect_timeout_error_display() {
        let err = ConnectTimeoutError {
            timeout: Duration::from_secs(5),
            peer_node: 42,
            started_at: now(),
            timed_out_at: now(),
        };
        let s = format!("{err}");
        assert!(s.contains("42"));
        assert!(s.contains("5"));
    }

    // ---- Debug output ----

    #[test]
    fn debug_output_contains_fields() {
        let lc = ConnectLifecycle::new(10, 20, now(), ConnectConfig::default());
        let s = format!("{lc:?}");
        assert!(s.contains("ConnectLifecycle"));
        assert!(s.contains("10"));
        assert!(s.contains("20"));
        assert!(s.contains("Connecting"));
    }

    // ---- Zero-duration timeout ----

    #[test]
    fn zero_duration_timeout_fires_immediately() {
        let start = now();
        let mut lc =
            ConnectLifecycle::new(1, 2, start, ConnectConfig::with_timeout(Duration::ZERO));
        // Zero-duration should fire at the exact start time
        assert!(lc.check_timeout(start));
        let result = lc.transition_to_dead_on_timeout(start).unwrap();
        assert!(result.is_some());
    }

    // ---- ConnectTimeoutError implements Error ----

    #[test]
    fn connect_timeout_error_is_std_error() {
        fn _assert_error<T: std::error::Error>(_: &T) {}
        let err = ConnectTimeoutError {
            timeout: Duration::from_secs(1),
            peer_node: 1,
            started_at: now(),
            timed_out_at: now(),
        };
        _assert_error(&err);
    }

    // ---- SessionLifecycle Eq + Hash ----

    #[test]
    fn lifecycle_eq_and_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SessionLifecycle::Connecting);
        set.insert(SessionLifecycle::Ready);
        set.insert(SessionLifecycle::Dead);
        assert_eq!(set.len(), 3);
        // Inserting duplicates should not grow the set
        set.insert(SessionLifecycle::Connecting);
        assert_eq!(set.len(), 3);
    }
}
