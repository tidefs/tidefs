//! Per-address outbound connection-attempt tracking with duplicate-prevention
//! and cooldown.
//!
//! ## Purpose
//!
//! The transport outbound connect path in [`connection`](crate::connection)
//! already guards against concurrent `connect()` calls to the same
//! `SocketAddr` via its internal connection table. However, the guard is
//! reactive: the caller learns about a duplicate attempt only after the OS
//! `connect()` has been reached, and failed-connect cooldown is not
//! modelled.
//!
//! This module provides a lightweight, caller-facing tracker that sits
//! _before_ the OS `connect()` call:
//!
//! - `try_begin_connect()` gates the outbound call; concurrent attempts to
//!   the same `(MemberId, TransportAddr)` return `Err(WouldBlock)`.
//! - On connect success, `mark_connected()` records the `SessionId`.
//! - On connect failure, the address enters a cooldown period. While in
//!   cooldown, `try_begin_connect()` returns `Err(WouldBlock)`.
//! - `prune_expired_cooldowns()` removes stale cooldown entries.
//!
//! ## State transitions
//!
//! ```text
//!               try_begin_connect()
//!  (no entry) ----------------------> Connecting
//!      ^                                  |
//!      |                                  +-- mark_connected() --> Connected(SessionId)
//!      |                                  |
//!      | cooldown expired                 +-- mark_failed() --> Cooldown(Instant)
//!      |                                       |
//!      +---------------------------------------+
//! ```
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::connect_tracker::{
//!     ConnectTimeout, ConnectionStateTracker,
//! };
//!
//! let timeout = ConnectTimeout::default(); // 5 s
//! let tracker = ConnectionStateTracker::new(std::time::Duration::from_secs(10));
//!
//! match tracker.try_begin_connect(member_id, addr.clone()) {
//!     Ok(()) => { /* proceed to OS connect() */ }
//!     Err(_) => { /* already connecting or in cooldown */ }
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::addr::TransportAddr;
use crate::error::TransportError;
use crate::types::SessionId;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// ConnectTimeout
// ---------------------------------------------------------------------------

/// Configurable connect-timeout for outbound session establishment.
///
/// Carries a [`Duration`] deadline that the caller should apply when
/// issuing the OS-level `connect()` call. The default is 5 seconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConnectTimeout {
    /// The connect deadline.
    pub duration: Duration,
}

impl ConnectTimeout {
    /// Create a new `ConnectTimeout` with the given duration.
    #[must_use]
    pub const fn new(duration: Duration) -> Self {
        Self { duration }
    }

    /// Create a `ConnectTimeout` from a number of seconds.
    #[must_use]
    pub const fn from_secs(secs: u64) -> Self {
        Self {
            duration: Duration::from_secs(secs),
        }
    }

    /// Create a `ConnectTimeout` from a number of milliseconds.
    #[must_use]
    pub const fn from_millis(millis: u64) -> Self {
        Self {
            duration: Duration::from_millis(millis),
        }
    }
}

impl Default for ConnectTimeout {
    fn default() -> Self {
        Self {
            duration: Duration::from_secs(5),
        }
    }
}

impl fmt::Display for ConnectTimeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}ms", self.duration.as_millis())
    }
}

// ---------------------------------------------------------------------------
// ConnectAttemptState
// ---------------------------------------------------------------------------

/// Per-address state of an outbound connection attempt.
///
/// States progress from `Connecting` to either `Connected` or `Cooldown`
/// (via `Failed`). When a cooldown expires, the entry is eligible for
/// pruning and a new attempt can begin.
#[derive(Debug)]
pub enum ConnectAttemptState {
    /// A connect is in progress for this address.
    Connecting,
    /// The connection succeeded; carries the established [`SessionId`].
    Connected(SessionId),
    /// A connect attempt failed with the given error.
    Failed(Box<TransportError>),
    /// The address is in cooldown after a failed attempt until the
    /// enclosed [`Instant`].
    Cooldown(Instant),
}

/// A connect attempt cannot start because the address is busy or cooling down.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectBeginError;

impl ConnectAttemptState {
    /// Returns `true` if a connect is currently in progress.
    pub fn is_connecting(&self) -> bool {
        matches!(self, Self::Connecting)
    }

    /// Returns `true` if the address has an established session.
    pub fn is_connected(&self) -> bool {
        matches!(self, Self::Connected(_))
    }

    /// Returns `true` if the address is in the cooldown period.
    pub fn is_cooldown(&self) -> bool {
        matches!(self, Self::Cooldown(_))
    }

    /// Returns the [`SessionId`] if connected.
    pub fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::Connected(id) => Some(*id),
            _ => None,
        }
    }
}

impl fmt::Display for ConnectAttemptState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connecting => write!(f, "Connecting"),
            Self::Connected(id) => write!(f, "Connected({id})"),
            Self::Failed(_) => write!(f, "Failed"),
            Self::Cooldown(until) => write!(
                f,
                "Cooldown(remaining={:?})",
                until.saturating_duration_since(Instant::now())
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionStateTracker
// ---------------------------------------------------------------------------

/// Tracks per-address outbound connection-attempt state.
///
/// The tracker prevents duplicate concurrent `connect()` calls to the same
/// `(MemberId, TransportAddr)` pair and enforces a cooldown after connection
/// failures.
///
/// # Thread safety
///
/// All methods use an internal `Mutex<HashMap>` and are safe to call from
/// multiple threads. The lock is held only for the duration of each method
/// call.
pub struct ConnectionStateTracker {
    entries: Mutex<HashMap<(MemberId, TransportAddr), ConnectAttemptState>>,
    cooldown_duration: Duration,
}

impl ConnectionStateTracker {
    /// Create a new tracker with the given cooldown duration.
    ///
    /// After a failed connect, the address enters cooldown for
    /// `cooldown_duration`. Subsequent `try_begin_connect()` calls
    /// return `Err(ConnectBeginError)` until the cooldown expires.
    #[must_use]
    pub fn new(cooldown_duration: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            cooldown_duration,
        }
    }

    /// Attempt to begin a connect to the given member at the given address.
    ///
    /// Returns `Ok(())` if no concurrent attempt is in progress for this
    /// `(member_id, addr)` pair and the address is not in cooldown.
    ///
    /// Returns `Err(ConnectBeginError)` if a connect is already in progress, a session is
    /// already connected, or the address is in the cooldown period.
    pub fn try_begin_connect(
        &self,
        member_id: MemberId,
        addr: TransportAddr,
    ) -> Result<(), ConnectBeginError> {
        let key = (member_id, addr);
        let mut guard = self.entries.lock().unwrap();
        if let Some(state) = guard.get(&key) {
            match state {
                ConnectAttemptState::Connecting => {
                    return Err(ConnectBeginError);
                }
                ConnectAttemptState::Connected(_) => {
                    return Err(ConnectBeginError);
                }
                ConnectAttemptState::Cooldown(expiry) => {
                    if Instant::now() < *expiry {
                        return Err(ConnectBeginError);
                    }
                    // Cooldown expired: fall through to allow new attempt.
                }
                ConnectAttemptState::Failed(_) => {
                    // Previous failure without cooldown; allow new attempt.
                }
            }
        }
        guard.insert(key, ConnectAttemptState::Connecting);
        Ok(())
    }

    /// Mark a pending connect as successfully connected.
    ///
    /// Updates the entry for `(member_id, addr)` to `Connected(session_id)`.
    /// If no entry exists, one is created.
    pub fn mark_connected(&self, member_id: MemberId, addr: TransportAddr, session_id: SessionId) {
        let key = (member_id, addr);
        let mut guard = self.entries.lock().unwrap();
        guard.insert(key, ConnectAttemptState::Connected(session_id));
    }

    /// Mark a pending connect as failed.
    ///
    /// The entry for `(member_id, addr)` is placed into the cooldown state
    /// with an expiry of `now + cooldown_duration`.
    pub fn mark_failed(&self, member_id: MemberId, addr: TransportAddr, _error: TransportError) {
        let key = (member_id, addr);
        let mut guard = self.entries.lock().unwrap();
        let cooldown_expiry = Instant::now() + self.cooldown_duration;
        guard.insert(key, ConnectAttemptState::Cooldown(cooldown_expiry));
    }

    /// Place an address into the cooldown state explicitly.
    pub fn enter_cooldown(&self, member_id: MemberId, addr: TransportAddr) {
        let key = (member_id, addr);
        let mut guard = self.entries.lock().unwrap();
        guard.insert(
            key,
            ConnectAttemptState::Cooldown(Instant::now() + self.cooldown_duration),
        );
    }

    /// Remove all entries whose cooldown has expired.
    ///
    /// Returns the number of entries removed.
    pub fn prune_expired_cooldowns(&self) -> usize {
        let mut guard = self.entries.lock().unwrap();
        let before = guard.len();
        let now = Instant::now();
        guard.retain(|_, state| match state {
            ConnectAttemptState::Cooldown(expiry) => *expiry > now,
            _ => true,
        });
        before - guard.len()
    }

    /// Returns the number of tracked entries (all states).
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Returns the number of entries currently in cooldown.
    #[cfg(test)]
    pub fn cooldown_count(&self) -> usize {
        self.entries
            .lock()
            .unwrap()
            .values()
            .filter(|s| matches!(s, ConnectAttemptState::Cooldown(_)))
            .count()
    }
}

impl fmt::Debug for ConnectionStateTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.entries.lock().unwrap();
        f.debug_struct("ConnectionStateTracker")
            .field("entries", &guard.len())
            .field("cooldown_duration", &self.cooldown_duration)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn tcp_addr(port: u16) -> TransportAddr {
        TransportAddr::Tcp(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port,
        ))
    }

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // ------------------------------------------------------------------
    // ConnectTimeout
    // ------------------------------------------------------------------

    #[test]
    fn connect_timeout_default_is_5_seconds() {
        let ct = ConnectTimeout::default();
        assert_eq!(ct.duration, Duration::from_secs(5));
    }

    #[test]
    fn connect_timeout_from_secs() {
        let ct = ConnectTimeout::from_secs(10);
        assert_eq!(ct.duration, Duration::from_secs(10));
    }

    #[test]
    fn connect_timeout_from_millis() {
        let ct = ConnectTimeout::from_millis(2500);
        assert_eq!(ct.duration, Duration::from_millis(2500));
    }

    #[test]
    fn connect_timeout_display() {
        let ct = ConnectTimeout::from_millis(500);
        assert_eq!(format!("{ct}"), "500ms");
    }

    // ------------------------------------------------------------------
    // try_begin_connect
    // ------------------------------------------------------------------

    #[test]
    fn try_begin_connect_succeeds_for_unseen_address() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        assert!(tracker.try_begin_connect(member(1), tcp_addr(9000)).is_ok());
    }

    #[test]
    fn try_begin_connect_err_for_already_connecting() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        let m = member(1);
        let a = tcp_addr(9001);

        assert!(tracker.try_begin_connect(m, a.clone()).is_ok());
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    #[test]
    fn try_begin_connect_err_for_already_connected() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        let m = member(1);
        let a = tcp_addr(9002);

        tracker.mark_connected(m, a.clone(), SessionId::new(42));
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    #[test]
    fn try_begin_connect_err_during_cooldown() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(3600)); // 1h
        let m = member(1);
        let a = tcp_addr(9003);

        tracker.mark_failed(
            m,
            a.clone(),
            TransportError::ConnectFailed {
                peer_addr: a.clone(),
                source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope"),
            },
        );
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    #[test]
    fn try_begin_connect_succeeds_after_cooldown_expires() {
        let tracker = ConnectionStateTracker::new(Duration::ZERO);
        let m = member(1);
        let a = tcp_addr(9004);

        tracker.mark_failed(
            m,
            a.clone(),
            TransportError::ConnectFailed {
                peer_addr: a.clone(),
                source: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "nope"),
            },
        );
        assert!(
            tracker.try_begin_connect(m, a).is_ok(),
            "should succeed after zero-duration cooldown"
        );
    }

    #[test]
    fn try_begin_connect_different_addresses_are_independent() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        let m = member(1);
        let a1 = tcp_addr(9005);
        let a2 = tcp_addr(9006);

        assert!(tracker.try_begin_connect(m, a1.clone()).is_ok());
        assert!(tracker.try_begin_connect(m, a2.clone()).is_ok());
    }

    #[test]
    fn try_begin_connect_different_members_same_addr_independent() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        let m1 = member(1);
        let m2 = member(2);
        let a = tcp_addr(9007);

        assert!(tracker.try_begin_connect(m1, a.clone()).is_ok());
        assert!(tracker.try_begin_connect(m2, a).is_ok());
    }

    // ------------------------------------------------------------------
    // State transitions
    // ------------------------------------------------------------------

    #[test]
    fn state_transition_connecting_to_connected() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(10));
        let m = member(1);
        let a = tcp_addr(9008);

        tracker.try_begin_connect(m, a.clone()).unwrap();
        tracker.mark_connected(m, a.clone(), SessionId::new(1));
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    #[test]
    fn state_transition_connecting_to_failed_to_cooldown() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(3600));
        let m = member(1);
        let a = tcp_addr(9009);

        tracker.try_begin_connect(m, a.clone()).unwrap();
        tracker.mark_failed(
            m,
            a.clone(),
            TransportError::ConnectFailed {
                peer_addr: a.clone(),
                source: std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"),
            },
        );

        assert_eq!(tracker.cooldown_count(), 1);
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    #[test]
    fn enter_cooldown_explicit() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(3600));
        let m = member(1);
        let a = tcp_addr(9010);

        tracker.enter_cooldown(m, a.clone());
        assert_eq!(tracker.cooldown_count(), 1);
        assert!(tracker.try_begin_connect(m, a).is_err());
    }

    // ------------------------------------------------------------------
    // prune_expired_cooldowns
    // ------------------------------------------------------------------

    #[test]
    fn prune_expired_cooldowns_removes_only_expired() {
        let tracker = ConnectionStateTracker::new(Duration::ZERO);
        let m = member(1);
        let a1 = tcp_addr(9011);
        let a2 = tcp_addr(9012);

        tracker.enter_cooldown(m, a1.clone());
        tracker.mark_connected(m, a2.clone(), SessionId::new(99));

        assert_eq!(tracker.entry_count(), 2);

        let pruned = tracker.prune_expired_cooldowns();
        assert_eq!(pruned, 1);
        assert_eq!(tracker.entry_count(), 1);
    }

    #[test]
    fn prune_expired_cooldowns_leaves_active_cooldowns() {
        let tracker = ConnectionStateTracker::new(Duration::from_secs(3600));
        let m = member(1);
        let a = tcp_addr(9013);

        tracker.enter_cooldown(m, a.clone());
        let pruned = tracker.prune_expired_cooldowns();
        assert_eq!(pruned, 0);
        assert_eq!(tracker.entry_count(), 1);
    }

    // ------------------------------------------------------------------
    // Concurrent access
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_try_begin_connect_exactly_one_succeeds() {
        use std::sync::Arc;
        use std::thread;

        let tracker = Arc::new(ConnectionStateTracker::new(Duration::from_secs(10)));
        let m = member(1);
        let a = tcp_addr(9014);

        let t1 = {
            let tracker = Arc::clone(&tracker);
            let a = a.clone();
            thread::spawn(move || tracker.try_begin_connect(m, a))
        };
        let t2 = {
            let tracker = Arc::clone(&tracker);
            let a = a.clone();
            thread::spawn(move || tracker.try_begin_connect(m, a))
        };

        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();

        let successes = [r1, r2].iter().filter(|r| r.is_ok()).count();
        assert_eq!(successes, 1, "exactly one thread should succeed");
    }

    // ------------------------------------------------------------------
    // ConnectAttemptState helpers
    // ------------------------------------------------------------------

    #[test]
    fn connect_attempt_state_is_connecting() {
        assert!(ConnectAttemptState::Connecting.is_connecting());
        assert!(!ConnectAttemptState::Connected(SessionId::new(1)).is_connecting());
        assert!(!ConnectAttemptState::Cooldown(Instant::now()).is_connecting());
    }

    #[test]
    fn connect_attempt_state_is_connected() {
        assert!(!ConnectAttemptState::Connecting.is_connected());
        assert!(ConnectAttemptState::Connected(SessionId::new(1)).is_connected());
        assert!(!ConnectAttemptState::Cooldown(Instant::now()).is_connected());
    }

    #[test]
    fn connect_attempt_state_is_cooldown() {
        assert!(!ConnectAttemptState::Connecting.is_cooldown());
        assert!(!ConnectAttemptState::Connected(SessionId::new(1)).is_cooldown());
        assert!(ConnectAttemptState::Cooldown(Instant::now()).is_cooldown());
    }

    #[test]
    fn connect_attempt_state_session_id() {
        assert_eq!(
            ConnectAttemptState::Connected(SessionId::new(42)).session_id(),
            Some(SessionId::new(42))
        );
        assert_eq!(ConnectAttemptState::Connecting.session_id(), None);
        assert_eq!(
            ConnectAttemptState::Cooldown(Instant::now()).session_id(),
            None
        );
    }
}
