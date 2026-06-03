//! Message send-deadline enforcement for stale-message cancellation.
//!
//! Protocol callers bound message lifetimes with optional
//! send deadlines. When a deadline is set, the send pipeline checks
//! before transmission whether the deadline has expired. Expired
//! messages are dropped and the caller is notified via a oneshot
//! channel attached at enqueue time.
//!
//! This prevents stale delivery after membership changes, lease
//! expiry, or epoch transitions without requiring each protocol
//! subsystem to implement its own timeout tracking.
//!
//! ## Quick start
//!
//! ```ignore
//! use tidefs_transport::send_deadline::{
//!     SendDeadlineConfig, MessageDeadline, DeadlineOutcome,
//! };
//! use std::time::Duration;
//!
//! let config = SendDeadlineConfig {
//!     enabled: true,
//!     default_deadline: Some(Duration::from_secs(30)),
//! };
//!
//! // Use with a SendPipelineHandle:
//! // let (token, outcome) = handle.send_with_deadline(
//! //     family, payload, Some(Duration::from_secs(5))
//! // ).await?;
//! // // token.wait().await -> DeadlineOutcome::Delivered or Cancelled
//! ```

use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::Instant;

// ---------------------------------------------------------------------------
// SendDeadlineConfig
// ---------------------------------------------------------------------------

/// Global configuration for send deadline enforcement.
///
/// Controls whether deadline checking is active and the default deadline
/// applied when a session does not set a session-level override.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SendDeadlineConfig {
    /// Whether deadline enforcement is enabled globally.
    /// When `false`, all deadline checks are skipped and no messages
    /// are cancelled for staleness.
    pub enabled: bool,
    /// Default message deadline applied when the caller does not
    /// provide an explicit deadline and the session has no override.
    /// `None` means no deadline by default.
    pub default_deadline: Option<Duration>,
}

// ---------------------------------------------------------------------------
// DeadlineOutcome
// ---------------------------------------------------------------------------

/// Outcome signalled to the caller via the deadline oneshot channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeadlineOutcome {
    /// The message was transmitted before its deadline expired.
    Delivered,
    /// The message was cancelled because its deadline had expired
    /// by the time the pipeline dequeued it.
    Cancelled,
}

// ---------------------------------------------------------------------------
// MessageDeadline
// ---------------------------------------------------------------------------

/// A message deadline: an optional [`Instant`] after which the
/// message is considered stale and may be cancelled.
///
/// `MessageDeadline` is cheap to clone and compare.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageDeadline(Option<Instant>);

impl MessageDeadline {
    /// No deadline — the message will never be cancelled for staleness.
    pub fn none() -> Self {
        Self(None)
    }

    /// Create a deadline `dur` from now.
    pub fn from_duration(dur: Duration) -> Self {
        Self(Some(Instant::now() + dur))
    }

    /// Create a deadline from an optional duration.
    /// `None` produces a deadline that never expires.
    pub fn from_opt_duration(dur: Option<Duration>) -> Self {
        match dur {
            Some(d) => Self::from_duration(d),
            None => Self::none(),
        }
    }

    /// Check whether the deadline has expired relative to the current
    /// time. Returns `false` when no deadline is set.
    pub fn is_expired(&self) -> bool {
        match self.0 {
            Some(deadline) => Instant::now() >= deadline,
            None => false,
        }
    }

    /// Return the inner instant, if any.
    pub fn as_instant(&self) -> Option<Instant> {
        self.0
    }

    /// Compute the remaining duration until the deadline, if set.
    /// Returns `None` when no deadline is set or the deadline has
    /// already expired (saturating to zero).
    pub fn remaining(&self) -> Option<Duration> {
        self.0.map(|deadline| {
            let now = Instant::now();
            if now >= deadline {
                Duration::ZERO
            } else {
                deadline - now
            }
        })
    }
}

// ---------------------------------------------------------------------------
// DeadlineToken
// ---------------------------------------------------------------------------

/// A receiver token returned to the caller when sending with a deadline.
///
/// The token resolves to [`DeadlineOutcome::Delivered`] when the message
/// is transmitted or [`DeadlineOutcome::Cancelled`] when it is dropped
/// due to deadline expiry.
#[derive(Debug)]
pub struct DeadlineToken {
    rx: oneshot::Receiver<DeadlineOutcome>,
}

impl DeadlineToken {
    /// Await the outcome of the send.
    pub async fn wait(self) -> Result<DeadlineOutcome, oneshot::error::RecvError> {
        self.rx.await
    }

    /// Try to obtain the outcome without blocking.
    pub fn try_wait(&mut self) -> Result<DeadlineOutcome, oneshot::error::TryRecvError> {
        self.rx.try_recv()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Create a paired [`DeadlineToken`] and [`oneshot::Sender`] for
/// deadline-cancellation signalling.
pub fn deadline_channel() -> (DeadlineToken, oneshot::Sender<DeadlineOutcome>) {
    let (tx, rx) = oneshot::channel();
    (DeadlineToken { rx }, tx)
}

/// Resolve a deadline for a message: use the caller-provided deadline if
/// present, otherwise fall back to the session default from config.
pub fn resolve_deadline(
    config: &SendDeadlineConfig,
    caller_deadline: Option<Duration>,
) -> MessageDeadline {
    if !config.enabled {
        return MessageDeadline::none();
    }
    match caller_deadline {
        Some(d) => MessageDeadline::from_duration(d),
        None => MessageDeadline::from_opt_duration(config.default_deadline),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // --- MessageDeadline tests ---

    #[test]
    fn deadline_none_never_expires() {
        let dl = MessageDeadline::none();
        assert!(!dl.is_expired());
        assert_eq!(dl.as_instant(), None);
    }

    #[test]
    fn deadline_future_not_expired() {
        let dl = MessageDeadline::from_duration(Duration::from_secs(3600));
        assert!(!dl.is_expired());
        assert!(dl.as_instant().is_some());
        let rem = dl.remaining().unwrap();
        assert!(rem > Duration::ZERO);
        assert!(rem <= Duration::from_secs(3600));
    }

    #[test]
    fn deadline_zero_expires_after_sleep() {
        let dl = MessageDeadline::from_duration(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(2));
        assert!(dl.is_expired());
        assert_eq!(dl.remaining(), Some(Duration::ZERO));
    }

    #[test]
    fn deadline_past_expires() {
        let dl = MessageDeadline::from_duration(Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(10));
        assert!(dl.is_expired());
    }

    #[test]
    fn deadline_from_opt_none_is_none() {
        let dl = MessageDeadline::from_opt_duration(None);
        assert!(!dl.is_expired());
        assert_eq!(dl.as_instant(), None);
    }

    #[test]
    fn deadline_from_opt_some_is_deadline() {
        let dl = MessageDeadline::from_opt_duration(Some(Duration::from_secs(60)));
        assert!(!dl.is_expired());
        assert!(dl.as_instant().is_some());
    }

    #[test]
    fn deadline_remaining_saturates_at_zero() {
        let dl = MessageDeadline::from_duration(Duration::ZERO);
        std::thread::sleep(Duration::from_millis(2));
        assert_eq!(dl.remaining(), Some(Duration::ZERO));
    }

    // --- SendDeadlineConfig tests ---

    #[test]
    fn config_default_is_disabled() {
        let cfg = SendDeadlineConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.default_deadline, None);
    }

    #[test]
    fn config_enabled_with_default() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: Some(Duration::from_secs(10)),
        };
        assert!(cfg.enabled);
        assert_eq!(cfg.default_deadline, Some(Duration::from_secs(10)));
    }

    #[test]
    fn config_disabled_skips_check() {
        let cfg = SendDeadlineConfig {
            enabled: false,
            default_deadline: Some(Duration::from_millis(1)),
        };
        let dl = resolve_deadline(&cfg, None);
        assert!(!dl.is_expired());
        assert_eq!(dl.as_instant(), None);
    }

    // --- resolve_deadline tests ---

    #[test]
    fn resolve_uses_caller_deadline_over_config_default() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: Some(Duration::from_secs(30)),
        };
        let dl = resolve_deadline(&cfg, Some(Duration::from_millis(5)));
        assert!(!dl.is_expired());
        let rem = dl.remaining().unwrap();
        assert!(rem <= Duration::from_millis(5));
    }

    #[test]
    fn resolve_falls_back_to_config_default() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: Some(Duration::from_secs(60)),
        };
        let dl = resolve_deadline(&cfg, None);
        assert!(!dl.is_expired());
        let rem = dl.remaining().unwrap();
        assert!(rem > Duration::ZERO);
        assert!(rem <= Duration::from_secs(60));
    }

    #[test]
    fn resolve_no_deadline_when_disabled() {
        let cfg = SendDeadlineConfig {
            enabled: false,
            default_deadline: Some(Duration::from_secs(5)),
        };
        let dl = resolve_deadline(&cfg, Some(Duration::from_secs(1)));
        assert_eq!(dl.as_instant(), None);
    }

    #[test]
    fn resolve_no_default_no_caller_deadline_gives_none() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: None,
        };
        let dl = resolve_deadline(&cfg, None);
        assert_eq!(dl.as_instant(), None);
    }

    // --- DeadlineToken tests ---

    #[tokio::test]
    async fn deadline_token_delivered() {
        let (token, tx) = deadline_channel();
        tx.send(DeadlineOutcome::Delivered).unwrap();
        let outcome = token.wait().await.unwrap();
        assert_eq!(outcome, DeadlineOutcome::Delivered);
    }

    #[tokio::test]
    async fn deadline_token_cancelled() {
        let (token, tx) = deadline_channel();
        tx.send(DeadlineOutcome::Cancelled).unwrap();
        let outcome = token.wait().await.unwrap();
        assert_eq!(outcome, DeadlineOutcome::Cancelled);
    }

    #[tokio::test]
    async fn deadline_token_try_wait_pending() {
        let (mut token, tx) = deadline_channel();
        // Before send, try_wait returns Empty error.
        let result = token.try_wait();
        assert!(result.is_err());
        // After send, try_wait returns the outcome.
        tx.send(DeadlineOutcome::Delivered).unwrap();
        let outcome = token.try_wait().unwrap();
        assert_eq!(outcome, DeadlineOutcome::Delivered);
    }

    #[tokio::test]
    async fn deadline_token_closed_sender_gives_err() {
        let (token, tx) = deadline_channel();
        drop(tx);
        let result = token.wait().await;
        assert!(result.is_err());
    }

    // --- Mixed-deadline tests ---

    #[test]
    fn mixed_deadline_and_no_deadline_in_config() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: None,
        };
        let dl_none = resolve_deadline(&cfg, None);
        let dl_some = resolve_deadline(&cfg, Some(Duration::from_secs(10)));
        assert_eq!(dl_none.as_instant(), None);
        assert!(dl_some.as_instant().is_some());
        assert!(!dl_some.is_expired());
    }

    #[test]
    fn immediate_expiry_with_config_enabled() {
        let cfg = SendDeadlineConfig {
            enabled: true,
            default_deadline: Some(Duration::ZERO),
        };
        let dl = resolve_deadline(&cfg, None);
        std::thread::sleep(Duration::from_millis(2));
        assert!(dl.is_expired());
    }

    #[test]
    fn deadline_boundary_edge_case_fresh_deadline_not_expired() {
        // A deadline set to 50ms from now should not be expired immediately.
        let dl = MessageDeadline::from_duration(Duration::from_millis(50));
        assert!(!dl.is_expired());
    }
}
