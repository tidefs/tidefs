// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Multi-session broadcast send for one-to-many message delivery.
//!
//! Enables efficient fan-out of a single message payload to a set of
//! target sessions without per-session re-encode overhead. The primary
//! use case is membership epoch distribution: a coordinator encodes the
//! committed-epoch view once and broadcasts it to all connected peers.
//!
//! Each target session independently applies its own epoch gating,
//! backpressure policy, and compression — one failing session does
//! not block delivery to others under the default best-effort mode.

use std::collections::BTreeMap;

use crate::message_priority::MessagePriority;
use crate::types::SessionId;
use crate::Transport;

// ---------------------------------------------------------------------------
// BroadcastConfig
// ---------------------------------------------------------------------------

/// Configuration for broadcast send behavior.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BroadcastConfig {
    /// How the broadcast handles individual session failures.
    pub failure_mode: BroadcastFailureMode,
    /// Maximum concurrent session sends.
    ///
    /// 0 means sequential (no concurrency). Values > 0 cap the number
    /// of session sends that may be in-flight at once when the transport
    /// uses async I/O. In the current synchronous transport, this field
    /// is advisory and broadcast always runs sequentially.
    pub parallelism: usize,
}

impl Default for BroadcastConfig {
    fn default() -> Self {
        Self {
            failure_mode: BroadcastFailureMode::BestEffort,
            parallelism: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// BroadcastFailureMode
// ---------------------------------------------------------------------------

/// Controls whether broadcast aborts or continues after a session error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastFailureMode {
    /// Stop at the first error; remaining targets are not attempted.
    FailFast,
    /// Continue through individual session failures, collecting all
    /// results so every target gets at least one attempt.
    BestEffort,
}

// ---------------------------------------------------------------------------
// BroadcastOutcome / BroadcastError
// ---------------------------------------------------------------------------

/// Per-session outcome from a broadcast send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastOutcome {
    /// The message was successfully accepted by the session's send path.
    Ok,
    /// The message was rejected or the session could not be reached.
    Err(BroadcastError),
}

/// Reason a broadcast send failed for a particular session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BroadcastError {
    /// The session ID does not exist in the transport session table.
    SessionNotFound,
    /// The session exists but is not in `Established` state.
    SessionNotEstablished,
    /// The send gate rejected this peer (not in committed roster).
    PeerNotInRoster,
    /// The session's send buffer is full and the backpressure policy
    /// is `Error` or `Block`.
    SendBufferFull,
    /// The session's send buffer has been shut down.
    SendBufferShutdown,
    /// The session is undergoing graceful drain with `reject_new_sends`.
    SessionDraining,
    /// An unexpected or uncategorized error occurred.
    Generic(String),
}

impl std::fmt::Display for BroadcastError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SessionNotFound => write!(f, "session not found"),
            Self::SessionNotEstablished => write!(f, "session not established"),
            Self::PeerNotInRoster => write!(f, "peer not in roster"),
            Self::SendBufferFull => write!(f, "send buffer full"),
            Self::SendBufferShutdown => write!(f, "send buffer shut down"),
            Self::SessionDraining => write!(f, "session draining"),
            Self::Generic(msg) => write!(f, "{msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// BroadcastResults
// ---------------------------------------------------------------------------

/// Collected outcomes from a broadcast send.
///
/// Maps each target [`SessionId`] to its [`BroadcastOutcome`].
/// Targets that were never attempted (e.g. because `FailFast` stopped
/// early) are absent from the map.
#[derive(Clone, Debug, Default)]
pub struct BroadcastResults {
    /// Per-session outcomes for every attempted target.
    pub outcomes: BTreeMap<SessionId, BroadcastOutcome>,
}

impl BroadcastResults {
    /// Create an empty results container.
    #[must_use]
    pub fn new() -> Self {
        Self {
            outcomes: BTreeMap::new(),
        }
    }

    /// All session IDs that succeeded.
    #[must_use]
    pub fn succeeded(&self) -> Vec<SessionId> {
        self.outcomes
            .iter()
            .filter_map(|(sid, outcome)| matches!(outcome, BroadcastOutcome::Ok).then_some(*sid))
            .collect()
    }

    /// All (session ID, error) pairs for sessions that failed.
    #[must_use]
    pub fn failed(&self) -> Vec<(SessionId, BroadcastError)> {
        self.outcomes
            .iter()
            .filter_map(|(sid, outcome)| {
                if let BroadcastOutcome::Err(ref err) = outcome {
                    Some((*sid, err.clone()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// True when every attempted target succeeded.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.outcomes
            .values()
            .all(|o| matches!(o, BroadcastOutcome::Ok))
    }

    /// Number of targets that succeeded.
    #[must_use]
    pub fn ok_count(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| matches!(o, BroadcastOutcome::Ok))
            .count()
    }

    /// Number of targets that failed.
    #[must_use]
    pub fn err_count(&self) -> usize {
        self.outcomes
            .values()
            .filter(|o| matches!(o, BroadcastOutcome::Err(_)))
            .count()
    }
}

// ---------------------------------------------------------------------------
// Transport::broadcast_send
// ---------------------------------------------------------------------------

impl Transport {
    /// Broadcast a single message payload to multiple sessions.
    ///
    /// The payload is encoded once by the caller and fanned out to every
    /// target session. Each session independently applies its own epoch
    /// gating, backpressure policy, and compression. Under the default
    /// [`BroadcastConfig`] (best-effort), one failing session does not
    /// block delivery to the remaining targets.
    ///
    /// # Empty target set
    ///
    /// Broadcasting to zero targets returns an empty `BroadcastResults`
    /// (all succeeded vacuously).
    ///
    /// # Example
    ///
    /// ```ignore
    /// use tidefs_transport::broadcast::{BroadcastConfig, BroadcastResults};
    ///
    /// let targets: Vec<SessionId> = roster_peers
    ///     .iter()
    ///     .filter_map(|peer| transport.session_for_peer(*peer))
    ///     .collect();
    ///
    /// let encoded_epoch = encode_committed_epoch_view(&epoch_view);
    /// let results = transport.broadcast_send(
    ///     &targets,
    ///     &encoded_epoch,
    ///     MessagePriority::Control,
    ///     &BroadcastConfig::default(),
    /// );
    ///
    /// for (sid, err) in results.failed() {
    ///     tracing::warn!(%sid, %err, "broadcast delivery failed");
    /// }
    /// ```
    pub fn broadcast_send(
        &mut self,
        targets: &[SessionId],
        payload: &[u8],
        priority: MessagePriority,
        config: &BroadcastConfig,
    ) -> BroadcastResults {
        let mut results = BroadcastResults::new();

        for &session_id in targets {
            // Check session exists and is in a sendable state first.
            // send_priority silently returns Ok(()) for missing or
            // non-established sessions, so we must pre-validate.
            let session_state_ok = self
                .sessions
                .get(&session_id)
                .and_then(|s| s.lock().ok())
                .map(|s| s.is_established())
                .unwrap_or(false);

            if !session_state_ok {
                let err = if self.sessions.contains_key(&session_id) {
                    BroadcastError::SessionNotEstablished
                } else {
                    BroadcastError::SessionNotFound
                };
                results
                    .outcomes
                    .insert(session_id, BroadcastOutcome::Err(err));
                if config.failure_mode == BroadcastFailureMode::FailFast {
                    break;
                }
                continue;
            }

            match self.send_priority(session_id, payload, priority) {
                Ok(()) => {
                    results.outcomes.insert(session_id, BroadcastOutcome::Ok);
                }
                Err(e) => {
                    let broadcast_err = map_transport_error_to_broadcast(&e);
                    results
                        .outcomes
                        .insert(session_id, BroadcastOutcome::Err(broadcast_err));

                    if config.failure_mode == BroadcastFailureMode::FailFast {
                        break;
                    }
                }
            }
        }

        results
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a [`crate::TransportError`] into a [`BroadcastError`].
fn map_transport_error_to_broadcast(err: &crate::error::TransportError) -> BroadcastError {
    match err {
        crate::error::TransportError::SessionNotFound { .. } => BroadcastError::SessionNotFound,
        crate::error::TransportError::SessionInWrongState { .. } => {
            BroadcastError::SessionNotEstablished
        }
        crate::error::TransportError::PeerNotInRoster { .. } => BroadcastError::PeerNotInRoster,
        crate::error::TransportError::SendBufferFull { .. } => BroadcastError::SendBufferFull,
        crate::error::TransportError::SendBufferShutdown { .. } => {
            BroadcastError::SendBufferShutdown
        }
        crate::error::TransportError::Generic(msg) => {
            if msg.contains("draining") {
                BroadcastError::SessionDraining
            } else {
                BroadcastError::Generic(msg.clone())
            }
        }
        _ => BroadcastError::Generic(err.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{message_priority::MessagePriority, types::SessionId, Transport};

    // -----------------------------------------------------------------------
    // BroadcastResults
    // -----------------------------------------------------------------------

    #[test]
    fn results_empty() {
        let r = BroadcastResults::new();
        assert!(r.succeeded().is_empty());
        assert!(r.failed().is_empty());
        assert!(r.all_ok());
        assert_eq!(r.ok_count(), 0);
        assert_eq!(r.err_count(), 0);
    }

    #[test]
    fn results_single_ok() {
        let mut r = BroadcastResults::new();
        r.outcomes.insert(SessionId::new(1), BroadcastOutcome::Ok);
        assert_eq!(r.succeeded(), vec![SessionId::new(1)]);
        assert!(r.failed().is_empty());
        assert!(r.all_ok());
        assert_eq!(r.ok_count(), 1);
        assert_eq!(r.err_count(), 0);
    }

    #[test]
    fn results_single_error() {
        let mut r = BroadcastResults::new();
        r.outcomes.insert(
            SessionId::new(1),
            BroadcastOutcome::Err(BroadcastError::SessionNotFound),
        );
        assert!(r.succeeded().is_empty());
        assert_eq!(
            r.failed(),
            vec![(SessionId::new(1), BroadcastError::SessionNotFound)]
        );
        assert!(!r.all_ok());
        assert_eq!(r.ok_count(), 0);
        assert_eq!(r.err_count(), 1);
    }

    #[test]
    fn results_mixed() {
        let mut r = BroadcastResults::new();
        r.outcomes.insert(SessionId::new(1), BroadcastOutcome::Ok);
        r.outcomes.insert(
            SessionId::new(2),
            BroadcastOutcome::Err(BroadcastError::SessionDraining),
        );
        r.outcomes.insert(SessionId::new(3), BroadcastOutcome::Ok);
        assert_eq!(r.succeeded(), vec![SessionId::new(1), SessionId::new(3)]);
        assert_eq!(
            r.failed(),
            vec![(SessionId::new(2), BroadcastError::SessionDraining)]
        );
        assert!(!r.all_ok());
        assert_eq!(r.ok_count(), 2);
        assert_eq!(r.err_count(), 1);
    }

    // -----------------------------------------------------------------------
    // BroadcastConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_is_best_effort() {
        let cfg = BroadcastConfig::default();
        assert_eq!(cfg.failure_mode, BroadcastFailureMode::BestEffort);
        assert_eq!(cfg.parallelism, 0);
    }

    // -----------------------------------------------------------------------
    // BroadcastError Display
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_error_display() {
        assert_eq!(
            BroadcastError::SessionNotFound.to_string(),
            "session not found"
        );
        assert_eq!(
            BroadcastError::SessionNotEstablished.to_string(),
            "session not established"
        );
        assert_eq!(
            BroadcastError::PeerNotInRoster.to_string(),
            "peer not in roster"
        );
        assert_eq!(
            BroadcastError::SendBufferFull.to_string(),
            "send buffer full"
        );
        assert_eq!(
            BroadcastError::SendBufferShutdown.to_string(),
            "send buffer shut down"
        );
        assert_eq!(
            BroadcastError::SessionDraining.to_string(),
            "session draining"
        );
        assert_eq!(BroadcastError::Generic("boom".into()).to_string(), "boom");
    }

    // -----------------------------------------------------------------------
    // broadcast_send: empty target set
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_empty_targets() {
        let mut transport = Transport::new(1001);
        let results = transport.broadcast_send(
            &[],
            b"epoch-data",
            MessagePriority::Control,
            &BroadcastConfig::default(),
        );
        assert!(results.outcomes.is_empty());
        assert!(results.all_ok());
    }

    // -----------------------------------------------------------------------
    // broadcast_send: non-existent session
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_nonexistent_session_best_effort() {
        let mut transport = Transport::new(1001);
        let targets = vec![SessionId::new(999)];
        let results = transport.broadcast_send(
            &targets,
            b"test",
            MessagePriority::Data,
            &BroadcastConfig::default(),
        );
        assert_eq!(results.err_count(), 1);
        let failures = results.failed();
        assert_eq!(failures[0].0, SessionId::new(999));
        assert!(matches!(failures[0].1, BroadcastError::SessionNotFound));
    }

    #[test]
    fn broadcast_nonexistent_session_fail_fast() {
        let mut transport = Transport::new(1001);
        let targets = vec![SessionId::new(1), SessionId::new(999), SessionId::new(2)];
        let results = transport.broadcast_send(
            &targets,
            b"fail-fast-test",
            MessagePriority::Data,
            &BroadcastConfig {
                failure_mode: BroadcastFailureMode::FailFast,
                ..BroadcastConfig::default()
            },
        );
        // FailFast stops at first error (session 1 is nonexistent),
        // so sessions 999 and 2 are never attempted.
        assert!(results.outcomes.contains_key(&SessionId::new(1)));
        assert!(!results.outcomes.contains_key(&SessionId::new(999)));
        assert!(!results.outcomes.contains_key(&SessionId::new(2)));
    }

    // -----------------------------------------------------------------------
    // broadcast_send: multiple sessions fail independently (best_effort)
    // -----------------------------------------------------------------------

    #[test]
    fn broadcast_multiple_nonexistent_best_effort() {
        let mut transport = Transport::new(1001);
        let targets = vec![SessionId::new(1), SessionId::new(2), SessionId::new(3)];
        let results = transport.broadcast_send(
            &targets,
            b"multi-test",
            MessagePriority::Control,
            &BroadcastConfig::default(),
        );
        // All three are nonexistent; best-effort tries every one.
        assert_eq!(results.err_count(), 3);
        assert!(results.succeeded().is_empty());
        for sid in &targets {
            assert!(matches!(
                results.outcomes.get(sid),
                Some(BroadcastOutcome::Err(BroadcastError::SessionNotFound))
            ));
        }
    }

    // -----------------------------------------------------------------------
    // Error mapping: TransportError -> BroadcastError
    // -----------------------------------------------------------------------

    #[test]
    fn map_session_not_found() {
        let err = crate::error::TransportError::SessionNotFound {
            session_id: SessionId::new(42),
        };
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::SessionNotFound
        );
    }

    #[test]
    fn map_session_wrong_state() {
        let err = crate::error::TransportError::SessionInWrongState {
            session_id: SessionId::new(7),
            expected: "Established",
            actual: "Connecting",
        };
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::SessionNotEstablished
        );
    }

    #[test]
    fn map_peer_not_in_roster() {
        let err = crate::error::TransportError::PeerNotInRoster {
            peer_id: 5,
            session_id: SessionId::new(10),
        };
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::PeerNotInRoster
        );
    }

    #[test]
    fn map_send_buffer_full() {
        let err = crate::error::TransportError::SendBufferFull {
            session_id: SessionId::new(3),
            capacity: 1024,
            needed: 512,
        };
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::SendBufferFull
        );
    }

    #[test]
    fn map_send_buffer_shutdown() {
        let err = crate::error::TransportError::SendBufferShutdown {
            session_id: SessionId::new(9),
        };
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::SendBufferShutdown
        );
    }

    #[test]
    fn map_draining_generic() {
        let err = crate::error::TransportError::Generic(
            "session is draining, rejecting new sends".into(),
        );
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::SessionDraining
        );
    }

    #[test]
    fn map_unknown_generic() {
        let err = crate::error::TransportError::Generic("something unexpected".into());
        assert_eq!(
            map_transport_error_to_broadcast(&err),
            BroadcastError::Generic("something unexpected".into())
        );
    }

    // -----------------------------------------------------------------------
    // BroadcastFailureMode: Clone/Copy/Debug/PartialEq
    // -----------------------------------------------------------------------

    #[test]
    fn failure_mode_is_copy() {
        let a = BroadcastFailureMode::FailFast;
        let b = a; // Copy
        assert_eq!(a, b);
    }

    #[test]
    fn broadcast_config_clone() {
        let cfg = BroadcastConfig {
            failure_mode: BroadcastFailureMode::FailFast,
            parallelism: 8,
        };
        let cfg2 = cfg.clone();
        assert_eq!(cfg, cfg2);
    }
}
