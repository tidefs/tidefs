//! Transport-level session reconnection with exponential backoff and jitter.
//!
//! ## Purpose
//!
//! When a transport session to a membership peer fails (TCP disconnect,
//! timeout, link flap), the [`SessionReconnector`] absorbs transient
//! failures through automatic reconnection attempts with increasing
//! backoff. This reduces false-positive membership churn: a single
//! transient network blip does not immediately escalate to membership
//! unreachability and roster removal.
//!
//! ## Relationship to other components
//!
//! - **ConnectionStateTracker** ([`crate::connect_tracker`]): the
//!   reconnector gates outbound reconnect attempts through the tracker
//!   to prevent duplicate concurrent connects to the same peer.
//! - **MembershipTransportBridge** ([`crate::epoch_bridge`]): on
//!   successful reconnection the reconnector signals peer-reachable;
//!   on permanent failure it signals the membership layer to escalate.
//! - **Unreachability detection** (#6137): the reconnector _delays_
//!   escalation to membership-level unreachability. Only after all
//!   reconnect attempts are exhausted does the membership layer
//!   consider the peer unreachable.
//!
//! ## Backoff algorithm
//!
//! For attempt `n` (0-indexed, where n=0 is the first retry after the
//! initial failure):
//!
//! ```text
//! raw_delay = min(base_delay * 2^n, max_delay)
//! jittered  = raw_delay * (1 +/- jitter_factor)
//! ```
//!
//! Jitter is uniform random within +/-`jitter_factor` of `raw_delay`,
//! bounded to be non-negative. This prevents thundering-herd
//! reconnection storms when multiple sessions fail simultaneously.
//!
//! ## Configuration defaults
//!
//! | Parameter         | Default | Description                              |
//! |-------------------|---------|------------------------------------------|
//! | `enabled`         | true    | Whether reconnection is active           |
//! | `base_delay`      | 1 s     | Initial backoff before first retry       |
//! | `max_delay`       | 60 s    | Hard cap on backoff duration             |
//! | `max_attempts`    | 10      | Max retry attempts before escalation     |
//! | `max_total_duration` | 300 s | Max total wall time before escalation   |
//! | `jitter_factor`   | 0.2     | +/-20% uniform jitter                    |
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::session_reconnector::{
//!     SessionReconnectConfig, SessionReconnector,
//! };
//!
//! let config = SessionReconnectConfig::default();
//! let reconnector = SessionReconnector::new(config);
//!
//! // On session close:
//! match reconnector.on_session_failed(member_id) {
//!     ReconnectAction::ReconnectAfter { delay, attempt } => {
//!         // schedule reconnect after `delay`
//!     }
//!     ReconnectAction::PermanentFailure { reason } => {
//!         // escalate to membership unreachability
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use rand::Rng;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// SessionReconnectConfig
// ---------------------------------------------------------------------------

/// Per-session reconnection configuration.
///
/// Each peer session can carry its own config; if unset the reconnector's
/// global default is used. All durations are wall-clock (not CPU time).
#[derive(Clone, Debug, PartialEq)]
pub struct SessionReconnectConfig {
    /// Whether automatic reconnection is enabled for this session.
    /// When `false`, session failure immediately produces
    /// [`ReconnectAction::PermanentFailure`] with reason [`PermanentFailureReason::Disabled`].
    pub enabled: bool,

    /// Base backoff delay before the first retry attempt.
    /// Default: 1 second.
    pub base_delay: Duration,

    /// Hard cap on the backoff delay after exponential growth.
    /// Default: 60 seconds.
    pub max_delay: Duration,

    /// Maximum number of reconnection attempts before escalating to
    /// permanent failure. Must be >= 1.
    /// Default: 10.
    pub max_attempts: u32,

    /// Maximum total wall-clock duration from the initial failure to
    /// the final attempt. If this duration is exceeded before
    /// `max_attempts` is reached, the reconnector escalates.
    /// Default: 300 seconds (5 minutes).
    pub max_total_duration: Duration,

    /// Jitter fraction applied to the computed backoff delay.
    /// Valid range: [0.0, 0.5]. 0.2 means +/-20% uniform jitter.
    /// Default: 0.2.
    pub jitter_factor: f64,
}

impl SessionReconnectConfig {
    /// Create a new config with explicit values.
    ///
    /// # Panics
    ///
    /// Panics if `max_attempts` is 0, `base_delay` is zero,
    /// `max_delay` < `base_delay`, `max_total_duration` is zero,
    /// or `jitter_factor` is outside [0.0, 0.5].
    #[must_use]
    pub fn new(
        enabled: bool,
        base_delay: Duration,
        max_delay: Duration,
        max_attempts: u32,
        max_total_duration: Duration,
        jitter_factor: f64,
    ) -> Self {
        assert!(max_attempts > 0, "max_attempts must be >= 1");
        assert!(base_delay > Duration::ZERO, "base_delay must be > 0");
        assert!(max_delay >= base_delay, "max_delay must be >= base_delay");
        assert!(
            max_total_duration > Duration::ZERO,
            "max_total_duration must be > 0"
        );
        assert!(
            (0.0..=0.5).contains(&jitter_factor),
            "jitter_factor must be in [0.0, 0.5]"
        );
        Self {
            enabled,
            base_delay,
            max_delay,
            max_attempts,
            max_total_duration,
            jitter_factor,
        }
    }

    /// Validate the configuration without panicking.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_attempts == 0 {
            return Err("max_attempts must be >= 1");
        }
        if self.base_delay == Duration::ZERO {
            return Err("base_delay must be > 0");
        }
        if self.max_delay < self.base_delay {
            return Err("max_delay must be >= base_delay");
        }
        if self.max_total_duration == Duration::ZERO {
            return Err("max_total_duration must be > 0");
        }
        if !(0.0..=0.5).contains(&self.jitter_factor) {
            return Err("jitter_factor must be in [0.0, 0.5]");
        }
        Ok(())
    }
}

impl Default for SessionReconnectConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(60),
            max_attempts: 10,
            max_total_duration: Duration::from_secs(300),
            jitter_factor: 0.2,
        }
    }
}

// ---------------------------------------------------------------------------
// PermanentFailureReason
// ---------------------------------------------------------------------------

/// Why the reconnector escalated to permanent failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermanentFailureReason {
    /// Reconnection is disabled for this session.
    Disabled,
    /// All retry attempts were exhausted without successful reconnection.
    MaxAttemptsExceeded {
        /// Number of attempts made.
        attempts: u32,
        /// Configured maximum.
        max: u32,
    },
    /// The total wall-clock duration since the initial failure exceeded
    /// the configured maximum.
    MaxDurationExceeded {
        /// Time elapsed since the initial failure.
        elapsed: Duration,
        /// Configured maximum duration.
        max: Duration,
    },
}

impl fmt::Display for PermanentFailureReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "reconnection disabled"),
            Self::MaxAttemptsExceeded { attempts, max } => {
                write!(f, "max attempts exceeded ({attempts}/{max})")
            }
            Self::MaxDurationExceeded { elapsed, max } => {
                write!(
                    f,
                    "max duration exceeded ({elapsed:?} elapsed, {max:?} max)"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ReconnectAction
// ---------------------------------------------------------------------------

/// Action the caller should take after querying the reconnector.
#[derive(Clone, Debug, PartialEq)]
pub enum ReconnectAction {
    /// Schedule a reconnection attempt after the given delay.
    /// `attempt` is 1-based (first retry = 1).
    ReconnectAfter {
        /// How long to wait before attempting reconnection.
        delay: Duration,
        /// Which attempt this is (1-based).
        attempt: u32,
    },
    /// Reconnection has been exhausted; escalate to membership
    /// unreachability detection.
    PermanentFailure {
        /// Why reconnection was abandoned.
        reason: PermanentFailureReason,
    },
}

// ---------------------------------------------------------------------------
// PerSessionState
// ---------------------------------------------------------------------------

/// Backoff state for a single peer session.
#[derive(Clone, Debug)]
struct PerSessionState {
    /// Number of reconnection attempts made so far (0 = no retry yet).
    attempt: u32,
    /// The last computed backoff duration.
    current_backoff: Duration,
    /// When the initial session failure was recorded.
    started_at: Instant,
}

impl PerSessionState {
    fn new() -> Self {
        Self {
            attempt: 0,
            current_backoff: Duration::ZERO,
            started_at: Instant::now(),
        }
    }

    /// Compute the next backoff duration and increment the attempt counter.
    fn advance(&mut self, config: &SessionReconnectConfig) -> Duration {
        self.attempt += 1;
        let raw = mul_duration_f64(config.base_delay, 2.0_f64.powi(self.attempt as i32 - 1))
            .min(config.max_delay);
        let jittered = apply_jitter(raw, config.jitter_factor);
        self.current_backoff = jittered;
        jittered
    }
}

// ---------------------------------------------------------------------------
// SessionReconnector
// ---------------------------------------------------------------------------

/// Manages per-peer session reconnection state with exponential backoff.
///
/// The reconnector is a passive state machine: the transport layer calls
/// into it on session lifecycle events, and it returns the action to take.
/// It does not spawn timers or perform I/O itself.
///
/// # Thread safety
///
/// All methods use an internal `Mutex<HashMap>` and are safe to call from
/// multiple threads. The lock is held only for the duration of each method
/// call.
///
/// # Lifecycle
///
/// 1. When a session fails, call [`on_session_failed`](Self::on_session_failed).
///    If the returned action is `ReconnectAfter`, schedule a reconnect.
/// 2. When a scheduled reconnect attempt succeeds, call
///    [`on_reconnect_success`](Self::on_reconnect_success) to reset backoff state.
/// 3. When a scheduled reconnect attempt fails, call
///    [`on_reconnect_failure`](Self::on_reconnect_failure) to advance the
///    backoff. If it returns `PermanentFailure`, escalate.
pub struct SessionReconnector {
    /// Global default config for sessions without per-session overrides.
    default_config: SessionReconnectConfig,
    /// Per-peer reconnection state.
    states: Mutex<HashMap<MemberId, PerSessionState>>,
}

impl SessionReconnector {
    /// Create a new reconnector with the given default configuration.
    #[must_use]
    pub fn new(default_config: SessionReconnectConfig) -> Self {
        Self {
            default_config,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Called when a transport session to `member_id` has failed.
    ///
    /// Returns the action to take. If reconnection is disabled, returns
    /// `PermanentFailure` immediately.
    ///
    /// On the first failure for a peer, records the start time and
    /// computes the first backoff delay. On subsequent failures,
    /// advances the backoff.
    pub fn on_session_failed(&self, member_id: MemberId) -> ReconnectAction {
        if !self.default_config.enabled {
            return ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::Disabled,
            };
        }

        let mut guard = self.states.lock().unwrap();
        let state = guard.entry(member_id).or_insert_with(PerSessionState::new);

        // Check max_attempts before advancing
        if state.attempt >= self.default_config.max_attempts {
            return ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::MaxAttemptsExceeded {
                    attempts: state.attempt,
                    max: self.default_config.max_attempts,
                },
            };
        }

        // Check max_total_duration
        let elapsed = state.started_at.elapsed();
        if elapsed >= self.default_config.max_total_duration {
            return ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::MaxDurationExceeded {
                    elapsed,
                    max: self.default_config.max_total_duration,
                },
            };
        }

        let delay = state.advance(&self.default_config);
        ReconnectAction::ReconnectAfter {
            delay,
            attempt: state.attempt,
        }
    }

    /// Called when a reconnection attempt for `member_id` succeeds.
    ///
    /// Resets the backoff state so the next failure starts from the
    /// initial backoff again.
    pub fn on_reconnect_success(&self, member_id: MemberId) {
        let mut guard = self.states.lock().unwrap();
        guard.remove(&member_id);
    }

    /// Called when a reconnection attempt for `member_id` fails.
    ///
    /// Advances the backoff and returns the next action. May return
    /// `PermanentFailure` if limits are exceeded.
    pub fn on_reconnect_failure(&self, member_id: MemberId) -> ReconnectAction {
        let mut guard = self.states.lock().unwrap();

        let state = match guard.get_mut(&member_id) {
            Some(s) => s,
            None => {
                // No state exists; treat as initial failure
                drop(guard);
                return self.on_session_failed(member_id);
            }
        };

        // Check max_attempts before advancing
        if state.attempt >= self.default_config.max_attempts {
            return ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::MaxAttemptsExceeded {
                    attempts: state.attempt,
                    max: self.default_config.max_attempts,
                },
            };
        }

        // Check max_total_duration
        let elapsed = state.started_at.elapsed();
        if elapsed >= self.default_config.max_total_duration {
            return ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::MaxDurationExceeded {
                    elapsed,
                    max: self.default_config.max_total_duration,
                },
            };
        }

        let delay = state.advance(&self.default_config);
        ReconnectAction::ReconnectAfter {
            delay,
            attempt: state.attempt,
        }
    }

    /// Explicitly reset reconnection state for a peer (e.g., on graceful
    /// disconnect where no reconnection is desired).
    pub fn reset(&self, member_id: MemberId) {
        let mut guard = self.states.lock().unwrap();
        guard.remove(&member_id);
    }

    /// Returns the current attempt count for a peer, or `None` if no
    /// reconnection is in progress.
    pub fn attempt_for(&self, member_id: MemberId) -> Option<u32> {
        let guard = self.states.lock().unwrap();
        guard.get(&member_id).map(|s| s.attempt)
    }

    /// Returns the number of peers currently in the reconnection state.
    #[cfg(test)]
    pub fn active_count(&self) -> usize {
        self.states.lock().unwrap().len()
    }

    /// Returns whether the reconnector has any active reconnection state.
    #[cfg(test)]
    pub fn has_active(&self) -> bool {
        !self.states.lock().unwrap().is_empty()
    }
}

impl fmt::Debug for SessionReconnector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let guard = self.states.lock().unwrap();
        f.debug_struct("SessionReconnector")
            .field("default_config", &self.default_config)
            .field("active_sessions", &guard.len())
            .finish()
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
// Helper: apply uniform jitter
// ---------------------------------------------------------------------------

/// Apply uniform jitter to a duration. The result is in
/// `[base * (1 - fraction), base * (1 + fraction)]`, clamped to
/// non-negative.
#[must_use]
pub fn apply_jitter(base: Duration, fraction: f64) -> Duration {
    if fraction <= 0.0 {
        return base;
    }
    let base_ns = base.as_nanos() as f64;
    let range = base_ns * fraction;
    let mut rng = rand::thread_rng();
    let r: f64 = rng.gen();
    let offset_ns = r * range * 2.0 - range;
    let jittered_ns = (base_ns + offset_ns).max(0.0);
    Duration::from_nanos(jittered_ns as u64)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn member(id: u64) -> MemberId {
        MemberId::new(id)
    }

    // ------------------------------------------------------------------
    // SessionReconnectConfig
    // ------------------------------------------------------------------

    #[test]
    fn config_default_is_valid() {
        let cfg = SessionReconnectConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_default_values() {
        let cfg = SessionReconnectConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.base_delay, Duration::from_secs(1));
        assert_eq!(cfg.max_delay, Duration::from_secs(60));
        assert_eq!(cfg.max_attempts, 10);
        assert_eq!(cfg.max_total_duration, Duration::from_secs(300));
        assert_eq!(cfg.jitter_factor, 0.2);
    }

    #[test]
    fn config_disabled_is_valid() {
        let cfg = SessionReconnectConfig {
            enabled: false,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_zero_attempts() {
        let cfg = SessionReconnectConfig {
            max_attempts: 0,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_zero_base_delay() {
        let cfg = SessionReconnectConfig {
            base_delay: Duration::ZERO,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_max_lt_base() {
        let cfg = SessionReconnectConfig {
            base_delay: Duration::from_secs(10),
            max_delay: Duration::from_secs(5),
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_zero_max_duration() {
        let cfg = SessionReconnectConfig {
            max_total_duration: Duration::ZERO,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_rejects_jitter_out_of_bounds() {
        let cfg = SessionReconnectConfig {
            jitter_factor: 1.0,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_validation_accepts_zero_jitter() {
        let cfg = SessionReconnectConfig {
            jitter_factor: 0.0,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_validation_accepts_max_jitter() {
        let cfg = SessionReconnectConfig {
            jitter_factor: 0.5,
            ..SessionReconnectConfig::default()
        };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_new_panics_on_invalid() {
        let result = std::panic::catch_unwind(|| {
            SessionReconnectConfig::new(
                true,
                Duration::from_secs(1),
                Duration::from_secs(60),
                0, // invalid
                Duration::from_secs(300),
                0.2,
            )
        });
        assert!(result.is_err());
    }

    // ------------------------------------------------------------------
    // PermanentFailureReason
    // ------------------------------------------------------------------

    #[test]
    fn failure_reason_display() {
        assert_eq!(
            format!("{}", PermanentFailureReason::Disabled),
            "reconnection disabled"
        );
        assert_eq!(
            format!(
                "{}",
                PermanentFailureReason::MaxAttemptsExceeded {
                    attempts: 5,
                    max: 10
                }
            ),
            "max attempts exceeded (5/10)"
        );
        let reason = PermanentFailureReason::MaxDurationExceeded {
            elapsed: Duration::from_secs(30),
            max: Duration::from_secs(60),
        };
        let msg = format!("{reason}");
        assert!(msg.contains("max duration exceeded"));
    }

    // ------------------------------------------------------------------
    // apply_jitter
    // ------------------------------------------------------------------

    #[test]
    fn jitter_zero_fraction_returns_base() {
        let base = Duration::from_millis(1000);
        let result = apply_jitter(base, 0.0);
        assert_eq!(result, base);
    }

    #[test]
    fn jitter_stays_within_bounds() {
        let base = Duration::from_millis(1000);
        for _ in 0..100 {
            let j = apply_jitter(base, 0.2);
            let lower = Duration::from_micros(800_000); // 800ms = 1000 * 0.8
            let upper = Duration::from_micros(1_200_000); // 1200ms = 1000 * 1.2
            assert!(j >= lower, "jitter too low: {j:?} (base {base:?})");
            assert!(j <= upper, "jitter too high: {j:?} (base {base:?})");
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: disabled
    // ------------------------------------------------------------------

    #[test]
    fn disabled_config_returns_permanent_failure_immediately() {
        let config = SessionReconnectConfig {
            enabled: false,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);
        let action = reconnector.on_session_failed(member(1));
        assert!(matches!(
            action,
            ReconnectAction::PermanentFailure {
                reason: PermanentFailureReason::Disabled
            }
        ));
    }

    // ------------------------------------------------------------------
    // SessionReconnector: basic backoff sequence
    // ------------------------------------------------------------------

    #[test]
    fn initial_failure_produces_reconnect_after() {
        let config = SessionReconnectConfig::default();
        let reconnector = SessionReconnector::new(config);
        let action = reconnector.on_session_failed(member(1));
        match action {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 1);
                // base_delay = 1s, first backoff should be ~1s (+/- jitter)
                assert!(delay >= Duration::from_micros(800_000));
                assert!(delay <= Duration::from_micros(1_200_000));
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        }
    }

    #[test]
    fn backoff_increases_exponentially() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0, // disable jitter for deterministic test
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // First failure
        let a1 = reconnector.on_session_failed(member(1));
        let d1 = match a1 {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 1);
                delay
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        };
        assert_eq!(d1, Duration::from_secs(1));

        // Second failure
        let a2 = reconnector.on_reconnect_failure(member(1));
        let d2 = match a2 {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 2);
                delay
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        };
        assert_eq!(d2, Duration::from_secs(2));

        // Third failure
        let a3 = reconnector.on_reconnect_failure(member(1));
        let d3 = match a3 {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 3);
                delay
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        };
        assert_eq!(d3, Duration::from_secs(4));

        // Fourth failure
        let a4 = reconnector.on_reconnect_failure(member(1));
        let d4 = match a4 {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 4);
                delay
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        };
        assert_eq!(d4, Duration::from_secs(8));
    }

    #[test]
    fn backoff_caps_at_max_delay() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            max_delay: Duration::from_secs(5),
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // First: 1s
        reconnector.on_session_failed(member(1));
        // Second: 2s
        reconnector.on_reconnect_failure(member(1));
        // Third: 4s
        reconnector.on_reconnect_failure(member(1));
        // Fourth: would be 8s but capped at 5s
        let a = reconnector.on_reconnect_failure(member(1));
        match a {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 4);
                assert_eq!(delay, Duration::from_secs(5));
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: max_attempts exceeded
    // ------------------------------------------------------------------

    #[test]
    fn max_attempts_exceeded_returns_permanent_failure() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            max_attempts: 3,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // Attempt 1
        let a1 = reconnector.on_session_failed(member(1));
        assert!(matches!(a1, ReconnectAction::ReconnectAfter { .. }));

        // Attempt 2
        let a2 = reconnector.on_reconnect_failure(member(1));
        assert!(matches!(a2, ReconnectAction::ReconnectAfter { .. }));

        // Attempt 3
        let a3 = reconnector.on_reconnect_failure(member(1));
        assert!(matches!(a3, ReconnectAction::ReconnectAfter { .. }));

        // Attempt 4 -> exceeded
        let a4 = reconnector.on_reconnect_failure(member(1));
        match a4 {
            ReconnectAction::PermanentFailure { reason } => {
                assert!(matches!(
                    reason,
                    PermanentFailureReason::MaxAttemptsExceeded {
                        attempts: 3,
                        max: 3
                    }
                ));
            }
            other => panic!("expected PermanentFailure, got {other:?}"),
        }
    }

    #[test]
    fn max_attempts_exceeded_from_session_failed() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            max_attempts: 1,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // First failure uses the one allowed attempt
        let a1 = reconnector.on_session_failed(member(1));
        assert!(matches!(a1, ReconnectAction::ReconnectAfter { .. }));

        // Second on_session_failed should see attempt already at max
        let a2 = reconnector.on_session_failed(member(1));
        match a2 {
            ReconnectAction::PermanentFailure { reason } => {
                assert!(matches!(
                    reason,
                    PermanentFailureReason::MaxAttemptsExceeded { .. }
                ));
            }
            other => panic!("expected PermanentFailure, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: max_total_duration exceeded
    // ------------------------------------------------------------------

    #[test]
    fn max_duration_exceeded_returns_permanent_failure() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            max_attempts: 100,                  // plenty of attempts
            max_total_duration: Duration::ZERO, // instantly exceeded
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        let action = reconnector.on_session_failed(member(1));
        match action {
            ReconnectAction::PermanentFailure { reason } => {
                assert!(matches!(
                    reason,
                    PermanentFailureReason::MaxDurationExceeded { .. }
                ));
            }
            other => panic!("expected PermanentFailure, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: successful reconnection resets state
    // ------------------------------------------------------------------

    #[test]
    fn reconnect_success_resets_backoff() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // Fail a few times
        reconnector.on_session_failed(member(1));
        reconnector.on_reconnect_failure(member(1));
        assert_eq!(reconnector.attempt_for(member(1)), Some(2));

        // Success resets
        reconnector.on_reconnect_success(member(1));
        assert_eq!(reconnector.attempt_for(member(1)), None);

        // Next failure starts fresh at attempt 1
        let a = reconnector.on_session_failed(member(1));
        match a {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 1);
                assert_eq!(delay, Duration::from_secs(1));
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: independent sessions
    // ------------------------------------------------------------------

    #[test]
    fn multiple_sessions_have_independent_backoff() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        // Session 1: fail twice
        reconnector.on_session_failed(member(1));
        reconnector.on_reconnect_failure(member(1));
        assert_eq!(reconnector.attempt_for(member(1)), Some(2));

        // Session 2: fail once
        reconnector.on_session_failed(member(2));
        assert_eq!(reconnector.attempt_for(member(2)), Some(1));

        // Session 1 state unchanged
        assert_eq!(reconnector.attempt_for(member(1)), Some(2));

        // Session 2 gets its own backoff sequence
        let a = reconnector.on_reconnect_failure(member(2));
        match a {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 2);
                assert_eq!(delay, Duration::from_secs(2));
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: explicit reset
    // ------------------------------------------------------------------

    #[test]
    fn explicit_reset_removes_state() {
        let config = SessionReconnectConfig::default();
        let reconnector = SessionReconnector::new(config);

        reconnector.on_session_failed(member(1));
        assert!(reconnector.has_active());

        reconnector.reset(member(1));
        assert!(!reconnector.has_active());
        assert_eq!(reconnector.attempt_for(member(1)), None);
    }

    // ------------------------------------------------------------------
    // SessionReconnector: on_reconnect_failure without prior state
    // ------------------------------------------------------------------

    #[test]
    fn reconnect_failure_without_state_treated_as_initial() {
        let config = SessionReconnectConfig {
            jitter_factor: 0.0,
            ..SessionReconnectConfig::default()
        };
        let reconnector = SessionReconnector::new(config);

        let action = reconnector.on_reconnect_failure(member(1));
        match action {
            ReconnectAction::ReconnectAfter { delay, attempt } => {
                assert_eq!(attempt, 1);
                assert_eq!(delay, Duration::from_secs(1));
            }
            other => panic!("expected ReconnectAfter, got {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // SessionReconnector: active_count and has_active
    // ------------------------------------------------------------------

    #[test]
    fn active_count_tracks_peers() {
        let config = SessionReconnectConfig::default();
        let reconnector = SessionReconnector::new(config);

        assert_eq!(reconnector.active_count(), 0);
        assert!(!reconnector.has_active());

        reconnector.on_session_failed(member(1));
        assert_eq!(reconnector.active_count(), 1);
        assert!(reconnector.has_active());

        reconnector.on_session_failed(member(2));
        assert_eq!(reconnector.active_count(), 2);

        reconnector.on_reconnect_success(member(1));
        assert_eq!(reconnector.active_count(), 1);
    }

    // ------------------------------------------------------------------
    // PermanentFailureReason equality
    // ------------------------------------------------------------------

    #[test]
    fn permanent_failure_reason_equality() {
        let r1 = PermanentFailureReason::Disabled;
        let r2 = PermanentFailureReason::Disabled;
        assert_eq!(r1, r2);

        let r3 = PermanentFailureReason::MaxAttemptsExceeded {
            attempts: 5,
            max: 10,
        };
        let r4 = PermanentFailureReason::MaxAttemptsExceeded {
            attempts: 5,
            max: 10,
        };
        assert_eq!(r3, r4);

        let r5 = PermanentFailureReason::MaxAttemptsExceeded {
            attempts: 6,
            max: 10,
        };
        assert_ne!(r3, r5);
    }

    // ------------------------------------------------------------------
    // ReconnectAction equality
    // ------------------------------------------------------------------

    #[test]
    fn reconnect_action_equality() {
        let a1 = ReconnectAction::ReconnectAfter {
            delay: Duration::from_secs(1),
            attempt: 2,
        };
        let a2 = ReconnectAction::ReconnectAfter {
            delay: Duration::from_secs(1),
            attempt: 2,
        };
        assert_eq!(a1, a2);

        let a3 = ReconnectAction::ReconnectAfter {
            delay: Duration::from_secs(2),
            attempt: 2,
        };
        assert_ne!(a1, a3);
    }

    // ------------------------------------------------------------------
    // Debug output
    // ------------------------------------------------------------------

    #[test]
    fn reconnector_debug_format() {
        let config = SessionReconnectConfig::default();
        let reconnector = SessionReconnector::new(config);
        let debug_str = format!("{reconnector:?}");
        assert!(debug_str.contains("SessionReconnector"));
        assert!(debug_str.contains("active_sessions"));
    }

    // ------------------------------------------------------------------
    // Concurrent access
    // ------------------------------------------------------------------

    #[test]
    fn concurrent_session_failures_dont_panic() {
        use std::sync::Arc;
        use std::thread;

        let config = SessionReconnectConfig::default();
        let reconnector = Arc::new(SessionReconnector::new(config));

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let r = Arc::clone(&reconnector);
                thread::spawn(move || {
                    for _ in 0..10 {
                        let _ = r.on_session_failed(member(i));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}
