//! Transport error classification taxonomy and recovery action dispatch.
//!
//! This module provides systematic classification of connection-level errors
//! (TCP resets, timeouts, protocol violations, backpressure stalls) into a
//! typed taxonomy with per-error-type recovery action dispatch, replacing
//! ad-hoc error handling across the I/O runtime, send dispatch, and keepalive
//! modules.
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::error_classification::{
//!     ErrorClassifier, RecoveryDispatcher, RecoveryAction, TransportErrorKind,
//! };
//! use tidefs_transport::connection_registry::ConnectionId;
//!
//! let classifier = ErrorClassifier::new();
//! let conn_id = ConnectionId::new(1);
//!
//! let raw_err = std::io::Error::from_raw_os_error(libc::ECONNRESET);
//! let transport_err = classifier.classify(raw_err, conn_id);
//! assert_eq!(transport_err.kind, TransportErrorKind::ConnectionReset);
//!
//! let action = RecoveryDispatcher::default().dispatch(&transport_err);
//! assert_eq!(action, RecoveryAction::CloseConnection);
//! ```

use std::fmt;
use std::time::{Duration, SystemTime};

use crate::connection_registry::ConnectionId;

// ---------------------------------------------------------------------------
// TransportErrorKind
// ---------------------------------------------------------------------------

/// Typed taxonomy of transport error classes.
///
/// Each variant corresponds to a distinct failure mode requiring a specific
/// recovery strategy. The classifier maps raw OS errors and protocol-level
/// fault signals into these kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportErrorKind {
    /// TCP connection was reset by peer (RST).
    ConnectionReset,
    /// TCP connection was actively refused (no listener).
    ConnectionRefused,
    /// Connection timed out during establishment or idle.
    ConnectionTimeout,
    /// Protocol violation detected (bad magic, version mismatch, unexpected
    /// message sequence).
    ProtocolViolation,
    /// A multiplexed channel was closed by the remote peer.
    ChannelClosed,
    /// Outbound send queue is at capacity (soft backpressure).
    BackpressureStall,
    /// Keepalive heartbeat timeout; peer is unreachable.
    KeepaliveTimeout,
    /// Message exceeds the maximum allowed frame size.
    MessageTooLarge,
    /// Unknown or unsupported message family discriminant on wire.
    UnknownMessageFamily,
    /// Internal assertion, allocation, or logic failure.
    InternalError,
}

impl fmt::Display for TransportErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionReset => write!(f, "ConnectionReset"),
            Self::ConnectionRefused => write!(f, "ConnectionRefused"),
            Self::ConnectionTimeout => write!(f, "ConnectionTimeout"),
            Self::ProtocolViolation => write!(f, "ProtocolViolation"),
            Self::ChannelClosed => write!(f, "ChannelClosed"),
            Self::BackpressureStall => write!(f, "BackpressureStall"),
            Self::KeepaliveTimeout => write!(f, "KeepaliveTimeout"),
            Self::MessageTooLarge => write!(f, "MessageTooLarge"),
            Self::UnknownMessageFamily => write!(f, "UnknownMessageFamily"),
            Self::InternalError => write!(f, "InternalError"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransportError
// ---------------------------------------------------------------------------

/// A classified transport-layer error carrying kind, source connection,
/// optional underlying OS error, and capture timestamp.
#[derive(Debug)]
pub struct TransportError {
    /// The classified error kind.
    pub kind: TransportErrorKind,
    /// The connection on which the error occurred.
    pub conn_id: ConnectionId,
    /// The underlying I/O error, when available.
    pub source: Option<std::io::Error>,
    /// Wall-clock time when the error was captured.
    pub timestamp: SystemTime,
}

impl TransportError {
    /// Create a new `TransportError` with the current timestamp.
    pub fn new(
        kind: TransportErrorKind,
        conn_id: ConnectionId,
        source: Option<std::io::Error>,
    ) -> Self {
        Self {
            kind,
            conn_id,
            source,
            timestamp: SystemTime::now(),
        }
    }

    /// The age of this error since capture (wall-clock duration).
    pub fn age(&self) -> Result<Duration, std::time::SystemTimeError> {
        SystemTime::now().duration_since(self.timestamp)
    }
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref src) = self.source {
            write!(f, "{} on conn {}: {}", self.kind, self.conn_id, src)
        } else {
            write!(f, "{} on conn {}", self.kind, self.conn_id)
        }
    }
}

// ---------------------------------------------------------------------------
// ErrorClassifier
// ---------------------------------------------------------------------------

/// Classifies raw `std::io::Error` values into [`TransportErrorKind`] variants.
///
/// # Mapping table
///
/// | Raw OS error      | `TransportErrorKind`   |
/// |------------------|-------------------------|
/// | `ECONNRESET`      | `ConnectionReset`      |
/// | `ECONNREFUSED`    | `ConnectionRefused`    |
/// | `ETIMEDOUT`       | `ConnectionTimeout`    |
/// | `EPIPE`           | `ConnectionReset`      |
/// | `ENOMEM`          | `InternalError`        |
/// | unknown           | `InternalError`        |
///
/// Protocol-level faults (version mismatch, unknown family) are classified
/// by their call site via [`classify_kind`].
#[derive(Clone, Debug, Default)]
pub struct ErrorClassifier;

impl ErrorClassifier {
    /// Create a new `ErrorClassifier`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Classify a raw `std::io::Error` into a [`TransportError`].
    ///
    /// Maps the error's `raw_os_error()` to the appropriate kind. Falls
    /// back to [`TransportErrorKind::InternalError`] when the OS error
    /// code is unknown or unavailable.
    pub fn classify(&self, err: std::io::Error, conn_id: ConnectionId) -> TransportError {
        let kind = self.classify_kind(&err);
        TransportError::new(kind, conn_id, Some(err))
    }

    /// Classify a raw `std::io::Error` into a [`TransportErrorKind`].
    pub fn classify_kind(&self, err: &std::io::Error) -> TransportErrorKind {
        match err.raw_os_error() {
            Some(code) => os_error_to_kind(code),
            None => TransportErrorKind::InternalError,
        }
    }

    /// Build a [`TransportError`] from a known [`TransportErrorKind`] without
    /// an underlying I/O error (used for protocol-level faults).
    pub fn classify_kind_direct(
        &self,
        kind: TransportErrorKind,
        conn_id: ConnectionId,
    ) -> TransportError {
        TransportError::new(kind, conn_id, None)
    }
}

/// Map a raw OS error code to a [`TransportErrorKind`].
pub(crate) fn os_error_to_kind(code: i32) -> TransportErrorKind {
    // Use raw libc constants for portability.  These match Linux errno values
    // but also resolve on macOS via the libc crate.
    #[allow(non_upper_case_globals)]
    match code {
        c if c == libc::ECONNRESET => TransportErrorKind::ConnectionReset,
        c if c == libc::ECONNREFUSED => TransportErrorKind::ConnectionRefused,
        c if c == libc::ETIMEDOUT => TransportErrorKind::ConnectionTimeout,
        c if c == libc::EPIPE => TransportErrorKind::ConnectionReset,
        c if c == libc::ENOMEM => TransportErrorKind::InternalError,
        _ => TransportErrorKind::InternalError,
    }
}

// ---------------------------------------------------------------------------
// RecoveryAction
// ---------------------------------------------------------------------------

/// The recovery action to take for a classified error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecoveryAction {
    /// Retry the operation after the given backoff duration.
    Retry {
        /// Duration to wait before retrying.
        backoff: Duration,
    },
    /// Immediately close the connection.
    CloseConnection,
    /// Drain pending writes gracefully, then close.
    DrainAndClose,
    /// Report the error to the membership subsystem for peer-liveness
    /// tracking.
    ReportToMembership,
    /// Ignore the error (transient, no action needed).
    Ignore,
}

impl fmt::Display for RecoveryAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retry { backoff } => {
                write!(f, "Retry(backoff={}ms)", backoff.as_millis())
            }
            Self::CloseConnection => write!(f, "CloseConnection"),
            Self::DrainAndClose => write!(f, "DrainAndClose"),
            Self::ReportToMembership => write!(f, "ReportToMembership"),
            Self::Ignore => write!(f, "Ignore"),
        }
    }
}

// ---------------------------------------------------------------------------
// RecoveryDispatcher
// ---------------------------------------------------------------------------

/// Dispatches a classified [`TransportError`] to the appropriate
/// [`RecoveryAction`].
///
/// The default implementation provides a canonical mapping from error kinds
/// to recovery actions. Implementors may override individual mappings or
/// provide entirely custom dispatch logic.
pub trait RecoveryDispatcher: Send + Sync {
    /// Determine the recovery action for a classified error.
    fn dispatch(&self, error: &TransportError) -> RecoveryAction;
}

/// Default mapping from `TransportErrorKind` to `RecoveryAction`.
#[derive(Clone, Debug, Default)]
pub struct DefaultRecoveryDispatcher;

impl RecoveryDispatcher for DefaultRecoveryDispatcher {
    fn dispatch(&self, error: &TransportError) -> RecoveryAction {
        default_recovery_action(error.kind)
    }
}

/// Canonical error-kind-to-recovery-action mapping.
pub fn default_recovery_action(kind: TransportErrorKind) -> RecoveryAction {
    match kind {
        TransportErrorKind::ConnectionReset => RecoveryAction::CloseConnection,
        TransportErrorKind::ConnectionRefused => RecoveryAction::CloseConnection,
        TransportErrorKind::ConnectionTimeout => RecoveryAction::ReportToMembership,
        TransportErrorKind::ProtocolViolation => RecoveryAction::CloseConnection,
        TransportErrorKind::ChannelClosed => RecoveryAction::Ignore,
        TransportErrorKind::BackpressureStall => RecoveryAction::Retry {
            backoff: Duration::from_millis(10),
        },
        TransportErrorKind::KeepaliveTimeout => RecoveryAction::DrainAndClose,
        TransportErrorKind::MessageTooLarge => RecoveryAction::CloseConnection,
        TransportErrorKind::UnknownMessageFamily => RecoveryAction::CloseConnection,
        TransportErrorKind::InternalError => RecoveryAction::CloseConnection,
    }
}

// ---------------------------------------------------------------------------
// ErrorObserver
// ---------------------------------------------------------------------------

/// Pluggable observer notified on every classified error with its dispatched
/// recovery action.
///
/// Implementations can log, increment counters, feed membership liveness
/// trackers, or emit structured telemetry.
pub trait ErrorObserver: Send + Sync {
    /// Called after an error is classified and a recovery action is chosen.
    fn on_error(&self, error: &TransportError, action: RecoveryAction);
}

// ---------------------------------------------------------------------------
// TracingErrorObserver
// ---------------------------------------------------------------------------

/// An [`ErrorObserver`] that logs classified errors via `tracing::warn!`.
///
/// Useful as a default observer in I/O tasks that do not have a membership
/// or telemetry backend wired in.
#[derive(Clone, Debug, Default)]
pub struct TracingErrorObserver;

impl ErrorObserver for TracingErrorObserver {
    fn on_error(&self, error: &TransportError, action: RecoveryAction) {
        tracing::warn!(
            "transport error {} on conn {} — action: {}",
            error.kind,
            error.conn_id,
            action,
        );
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// ErrorRateTracker
// ---------------------------------------------------------------------------

/// Tracks error classification events and computes a rolling error rate
/// (errors per second) for consumption by the peer health scoring system
/// (#5885).
///
/// Maintains a sliding window of error timestamps. Older entries decay
/// out of the window after `window_duration`.
#[derive(Clone, Debug)]
pub struct ErrorRateTracker {
    /// Timestamps of recent errors within the window.
    timestamps: std::collections::VecDeque<std::time::Instant>,
    /// Duration of the sliding window.
    window_duration: std::time::Duration,
}

impl ErrorRateTracker {
    /// Create a new tracker with the given window duration.
    #[must_use]
    pub fn new(window_duration: std::time::Duration) -> Self {
        Self {
            timestamps: std::collections::VecDeque::new(),
            window_duration,
        }
    }

    /// Record a classified error event at the current time.
    pub fn record(&mut self) {
        let now = std::time::Instant::now();
        self.timestamps.push_back(now);
        self.prune(now);
    }

    /// Return the current error rate as errors per second.
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        if self.timestamps.is_empty() {
            return 0.0;
        }
        let elapsed = self
            .timestamps
            .back()
            .unwrap()
            .duration_since(*self.timestamps.front().unwrap());
        let secs = elapsed.as_secs_f64();
        if secs < 1e-9 {
            return 0.0;
        }
        self.timestamps.len() as f64 / secs
    }

    /// Feed the current error rate into a health signal sink.
    pub fn feed_health_rate(
        &self,
        sink: &mut dyn crate::peer_health::HealthSignalSink,
        conn_id: crate::connection_registry::ConnectionId,
    ) {
        let rate = self.error_rate();
        sink.ingest_signal(conn_id, crate::peer_health::HealthSignal::ErrorRate(rate));
    }

    /// Remove timestamps outside the sliding window.
    fn prune(&mut self, now: std::time::Instant) {
        let cutoff = now - self.window_duration;
        while let Some(&front) = self.timestamps.front() {
            if front < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
    }

    /// Number of errors currently in the window.
    #[must_use]
    pub fn len(&self) -> usize {
        self.timestamps.len()
    }

    /// Whether the tracker has no recorded errors in the window.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.timestamps.is_empty()
    }
}

impl Default for ErrorRateTracker {
    fn default() -> Self {
        Self::new(std::time::Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // OS error code classification
    // -----------------------------------------------------------------------

    #[test]
    fn connection_reset_maps_correctly() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::from_raw_os_error(libc::ECONNRESET);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::ConnectionReset);
    }

    #[test]
    fn connection_refused_maps_correctly() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::from_raw_os_error(libc::ECONNREFUSED);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::ConnectionRefused);
    }

    #[test]
    fn timeout_maps_correctly() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::from_raw_os_error(libc::ETIMEDOUT);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::ConnectionTimeout);
    }

    #[test]
    fn epipe_maps_to_connection_reset() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::from_raw_os_error(libc::EPIPE);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::ConnectionReset);
    }

    #[test]
    fn enomem_maps_to_internal_error() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::from_raw_os_error(libc::ENOMEM);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::InternalError);
    }

    #[test]
    fn unknown_errno_defaults_to_internal_error() {
        let classifier = ErrorClassifier::new();
        // EINVAL is not in the mapping table; should fall back.
        let err = std::io::Error::from_raw_os_error(libc::EINVAL);
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::InternalError);
    }

    #[test]
    fn non_os_error_defaults_to_internal_error() {
        let classifier = ErrorClassifier::new();
        let err = std::io::Error::other("custom error");
        assert!(err.raw_os_error().is_none());
        let kind = classifier.classify_kind(&err);
        assert_eq!(kind, TransportErrorKind::InternalError);
    }

    // -----------------------------------------------------------------------
    // Full classify (produces TransportError)
    // -----------------------------------------------------------------------

    #[test]
    fn classify_produces_correct_transport_error() {
        let classifier = ErrorClassifier::new();
        let conn_id = ConnectionId::new(42);
        let raw = std::io::Error::from_raw_os_error(libc::ECONNRESET);
        let transport_err = classifier.classify(raw, conn_id);

        assert_eq!(transport_err.kind, TransportErrorKind::ConnectionReset);
        assert_eq!(transport_err.conn_id, ConnectionId::new(42));
        assert!(transport_err.source.is_some());
        assert!(transport_err.timestamp <= SystemTime::now());
    }

    #[test]
    fn classify_kind_direct_no_source() {
        let classifier = ErrorClassifier::new();
        let conn_id = ConnectionId::new(7);
        let transport_err =
            classifier.classify_kind_direct(TransportErrorKind::ProtocolViolation, conn_id);

        assert_eq!(transport_err.kind, TransportErrorKind::ProtocolViolation);
        assert_eq!(transport_err.conn_id, ConnectionId::new(7));
        assert!(transport_err.source.is_none());
    }

    // -----------------------------------------------------------------------
    // TransportError Display
    // -----------------------------------------------------------------------

    #[test]
    fn transport_error_display_with_source() {
        let err = TransportError::new(
            TransportErrorKind::ConnectionReset,
            ConnectionId::new(1),
            Some(std::io::Error::from_raw_os_error(libc::ECONNRESET)),
        );
        let display = err.to_string();
        assert!(display.contains("ConnectionReset"));
        assert!(display.contains("conn:1"));
    }

    #[test]
    fn transport_error_display_without_source() {
        let err = TransportError::new(
            TransportErrorKind::InternalError,
            ConnectionId::new(99),
            None,
        );
        let display = err.to_string();
        assert!(display.contains("InternalError"));
        assert!(display.contains("conn:99"));
    }

    // -----------------------------------------------------------------------
    // TransportError age
    // -----------------------------------------------------------------------

    #[test]
    fn error_age_is_monotonic() {
        let earlier = TransportError::new(
            TransportErrorKind::ConnectionReset,
            ConnectionId::new(1),
            None,
        );
        std::thread::sleep(Duration::from_millis(5));
        let later = TransportError::new(
            TransportErrorKind::ConnectionReset,
            ConnectionId::new(1),
            None,
        );

        let earlier_age = earlier.age().unwrap();
        let later_age = later.age().unwrap();
        assert!(earlier_age > later_age,
            "earlier error should be older (larger age) than later error: earlier_age={earlier_age:?}, later_age={later_age:?}");
    }

    // -----------------------------------------------------------------------
    // RecoveryAction mapping correctness
    // -----------------------------------------------------------------------

    #[test]
    fn connection_reset_triggers_close() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::ConnectionReset,
            ConnectionId::new(1),
            None,
        );
        assert_eq!(dispatcher.dispatch(&err), RecoveryAction::CloseConnection);
    }

    #[test]
    fn connection_refused_triggers_close() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::ConnectionRefused,
            ConnectionId::new(1),
            None,
        );
        assert_eq!(dispatcher.dispatch(&err), RecoveryAction::CloseConnection);
    }

    #[test]
    fn connection_timeout_triggers_report_to_membership() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::ConnectionTimeout,
            ConnectionId::new(1),
            None,
        );
        assert_eq!(
            dispatcher.dispatch(&err),
            RecoveryAction::ReportToMembership
        );
    }

    #[test]
    fn protocol_violation_triggers_close() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::ProtocolViolation,
            ConnectionId::new(1),
            None,
        );
        assert_eq!(dispatcher.dispatch(&err), RecoveryAction::CloseConnection);
    }

    #[test]
    fn backpressure_stall_triggers_retry() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::BackpressureStall,
            ConnectionId::new(3),
            None,
        );
        assert_eq!(
            dispatcher.dispatch(&err),
            RecoveryAction::Retry {
                backoff: Duration::from_millis(10),
            }
        );
    }

    #[test]
    fn keepalive_timeout_triggers_drain_and_close() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::KeepaliveTimeout,
            ConnectionId::new(2),
            None,
        );
        assert_eq!(dispatcher.dispatch(&err), RecoveryAction::DrainAndClose);
    }

    #[test]
    fn channel_closed_triggers_ignore() {
        let dispatcher = DefaultRecoveryDispatcher;
        let err = TransportError::new(
            TransportErrorKind::ChannelClosed,
            ConnectionId::new(1),
            None,
        );
        assert_eq!(dispatcher.dispatch(&err), RecoveryAction::Ignore);
    }

    // -----------------------------------------------------------------------
    // ErrorObserver
    // -----------------------------------------------------------------------

    #[test]
    fn custom_error_observer_receives_notification() {
        struct TestObserver {
            received: Arc<Mutex<Vec<(TransportErrorKind, RecoveryAction)>>>,
        }
        impl ErrorObserver for TestObserver {
            fn on_error(&self, error: &TransportError, action: RecoveryAction) {
                self.received.lock().unwrap().push((error.kind, action));
            }
        }

        let received = Arc::new(Mutex::new(Vec::new()));
        let observer = TestObserver {
            received: Arc::clone(&received),
        };

        let err = TransportError::new(
            TransportErrorKind::ConnectionTimeout,
            ConnectionId::new(5),
            None,
        );
        let dispatcher = DefaultRecoveryDispatcher;
        let action = dispatcher.dispatch(&err);
        observer.on_error(&err, action);

        let entries = received.lock().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].0, TransportErrorKind::ConnectionTimeout);
        assert_eq!(entries[0].1, RecoveryAction::ReportToMembership);
    }

    // -----------------------------------------------------------------------
    // RecoveryAction Display
    // -----------------------------------------------------------------------

    #[test]
    fn recovery_action_retry_display() {
        let action = RecoveryAction::Retry {
            backoff: Duration::from_millis(50),
        };
        assert!(action.to_string().contains("50ms"));
    }

    #[test]
    fn recovery_action_close_display() {
        assert_eq!(
            RecoveryAction::CloseConnection.to_string(),
            "CloseConnection"
        );
    }

    // -----------------------------------------------------------------------
    // All error kinds have a default action (no panics)
    // -----------------------------------------------------------------------

    #[test]
    fn all_error_kinds_have_default_action() {
        let dispatcher = DefaultRecoveryDispatcher;
        let kinds = [
            TransportErrorKind::ConnectionReset,
            TransportErrorKind::ConnectionRefused,
            TransportErrorKind::ConnectionTimeout,
            TransportErrorKind::ProtocolViolation,
            TransportErrorKind::ChannelClosed,
            TransportErrorKind::BackpressureStall,
            TransportErrorKind::KeepaliveTimeout,
            TransportErrorKind::MessageTooLarge,
            TransportErrorKind::UnknownMessageFamily,
            TransportErrorKind::InternalError,
        ];

        for kind in &kinds {
            let err = TransportError::new(*kind, ConnectionId::new(0), None);
            let _action = dispatcher.dispatch(&err); // must not panic
        }
    }
}
