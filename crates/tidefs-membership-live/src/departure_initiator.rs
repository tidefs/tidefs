#![forbid(unsafe_code)]

//! Peer-side coordinated departure state machine.
//!
//! [`DepartureInitiator`] tracks the lifecycle of a peer's voluntary departure
//! from the cluster. The peer sends a [`DepartureRequest`] to the coordinator,
//! waits for the coordinator to gather quorum and advance the epoch, then
//! drains any in-flight work before confirming departure.
//!
//! ## State machine
//!
//! ```text
//! initiate(reason) → Pending
//!   |
//!   +-- on_response(Accepted) → QuorumVoting
//!   |     |
//!   |     +-- on_epoch_advance(epoch) → Committed
//!   |           |
//!   |           +-- drain_complete() → terminal (peer exits)
//!   |
//!   +-- on_response(Rejected) → Aborted
//!   +-- on_timeout() → Aborted
//! ```
//!
//! ## Integration
//!
//! The initiator is used by the peer's membership runtime when the operator
//! requests a voluntary departure. It does not handle coordinator-initiated
//! eviction — eviction is processed through
//! [`super::departure_coordinator::DepartureCoordinator`].

use std::time::{Duration, Instant};

use tidefs_membership_types::departure::{
    DepartureReason, DepartureRequest, DepartureResponse, DepartureState,
};

/// Errors returned by the departure initiator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InitiatorError {
    /// The initiator is not in the correct state for the requested operation.
    InvalidState {
        current: DepartureState,
        expected: &'static str,
    },
    /// The departure timed out waiting for coordinator response.
    Timeout,
    /// The departure was rejected by the coordinator.
    Rejected {
        /// Reason provided by the coordinator.
        reason: Option<String>,
    },
}

/// Configuration for the departure initiator.
#[derive(Clone, Debug)]
pub struct DepartureInitiatorConfig {
    /// Maximum time to wait for coordinator response before timing out.
    pub response_timeout: Duration,
    /// Maximum time to wait for quorum to complete and epoch to advance.
    pub quorum_timeout: Duration,
}

impl Default for DepartureInitiatorConfig {
    fn default() -> Self {
        Self {
            response_timeout: Duration::from_secs(30),
            quorum_timeout: Duration::from_secs(120),
        }
    }
}

// ---------------------------------------------------------------------------
// DepartureInitiator
// ---------------------------------------------------------------------------

/// Peer-side state machine for voluntary coordinated departure.
///
/// Tracks the lifecycle from initiation through quorum confirmation to
/// drain and final exit.
#[derive(Clone, Debug)]
pub struct DepartureInitiator {
    /// The peer requesting departure.
    pub peer_id: u64,
    /// Current departure state.
    pub state: DepartureState,
    /// Reason for departure (always Voluntary for peer-initiated).
    pub reason: DepartureReason,
    /// The epoch at which departure was requested.
    pub request_epoch: u64,
    /// Monotonic nonce for request deduplication.
    pub nonce: u64,
    /// Configurable timeouts.
    pub config: DepartureInitiatorConfig,
    /// Instant when the request was sent.
    request_sent_at: Option<Instant>,
    /// Instant when quorum voting started.
    quorum_started_at: Option<Instant>,
    /// Rejection reason, set when outcome is Rejected.
    pub rejection_reason: Option<String>,
    /// The successor epoch after departure, set when Committed.
    pub successor_epoch: Option<u64>,
}

impl DepartureInitiator {
    /// Create a new departure initiator for the given peer.
    #[must_use]
    pub fn new(
        peer_id: u64,
        request_epoch: u64,
        nonce: u64,
        config: DepartureInitiatorConfig,
    ) -> Self {
        Self {
            peer_id,
            state: DepartureState::Pending,
            reason: DepartureReason::Voluntary,
            request_epoch,
            nonce,
            config,
            request_sent_at: None,
            quorum_started_at: None,
            rejection_reason: None,
            successor_epoch: None,
        }
    }

    /// Create a new initiator with a custom nonce, mark as initiated.
    #[must_use]
    pub fn initiate(
        peer_id: u64,
        request_epoch: u64,
        nonce: u64,
        config: DepartureInitiatorConfig,
    ) -> Self {
        let mut s = Self::new(peer_id, request_epoch, nonce, config);
        s.state = DepartureState::Pending;
        s.request_sent_at = Some(Instant::now());
        s
    }

    /// Build the [`DepartureRequest`] to send to the coordinator.
    #[must_use]
    pub fn build_request(&self) -> DepartureRequest {
        DepartureRequest {
            peer_id: self.peer_id,
            reason: self.reason,
            request_epoch: self.request_epoch,
            nonce: self.nonce,
        }
    }

    /// Handle a departure response from the coordinator.
    ///
    /// On accepted, transitions to `QuorumVoting`.
    /// On rejected, transitions to `Aborted` with the rejection reason.
    ///
    /// # Errors
    ///
    /// Returns [`InitiatorError::InvalidState`] if not in `Pending` state.
    pub fn on_response(&mut self, response: &DepartureResponse) -> Result<(), InitiatorError> {
        if self.state != DepartureState::Pending {
            return Err(InitiatorError::InvalidState {
                current: self.state,
                expected: "Pending",
            });
        }

        match response.accepted {
            true => {
                self.state = DepartureState::QuorumVoting;
                self.quorum_started_at = Some(Instant::now());
            }
            false => {
                self.state = DepartureState::Aborted;
                self.rejection_reason = response.reject_reason.clone();
            }
        }
        Ok(())
    }

    /// Handle an epoch advancement from the coordinator.
    ///
    /// When the coordinator pushes a new epoch that does not include this
    /// peer, the departure is committed. Transitions to `Committed`.
    ///
    /// # Errors
    ///
    /// Returns [`InitiatorError::InvalidState`] if not in `QuorumVoting` state.
    pub fn on_epoch_advance(
        &mut self,
        new_epoch: u64,
        member_set: &[u64],
    ) -> Result<(), InitiatorError> {
        if self.state != DepartureState::QuorumVoting {
            return Err(InitiatorError::InvalidState {
                current: self.state,
                expected: "QuorumVoting",
            });
        }

        // Only commit if this peer is no longer in the member set.
        if !member_set.contains(&self.peer_id) {
            self.state = DepartureState::Committed;
            self.successor_epoch = Some(new_epoch);
        }
        Ok(())
    }

    /// Mark the drain phase as complete.
    ///
    /// After this, the peer can cleanly exit the cluster.
    ///
    /// # Errors
    ///
    /// Returns [`InitiatorError::InvalidState`] if not in `Committed` state.
    pub fn drain_complete(&mut self) -> Result<(), InitiatorError> {
        if self.state != DepartureState::Committed {
            return Err(InitiatorError::InvalidState {
                current: self.state,
                expected: "Committed",
            });
        }
        // Terminal state; peer exits after drain.
        Ok(())
    }

    /// Check for timeout and transition to Aborted if necessary.
    ///
    /// Returns `true` if the initiator was aborted due to timeout.
    #[must_use]
    pub fn check_timeout(&mut self, now: Instant) -> bool {
        match self.state {
            DepartureState::Pending => {
                if let Some(sent_at) = self.request_sent_at {
                    if now.duration_since(sent_at) >= self.config.response_timeout {
                        self.state = DepartureState::Aborted;
                        self.rejection_reason =
                            Some("timeout waiting for coordinator response".into());
                        return true;
                    }
                }
            }
            DepartureState::QuorumVoting => {
                if let Some(started_at) = self.quorum_started_at {
                    if now.duration_since(started_at) >= self.config.quorum_timeout {
                        self.state = DepartureState::Aborted;
                        self.rejection_reason = Some("timeout waiting for quorum".into());
                        return true;
                    }
                }
            }
            _ => {}
        }
        false
    }

    /// Whether the initiator has reached a terminal state.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            DepartureState::Committed | DepartureState::Aborted
        )
    }

    /// Whether the departure was successful (committed and drain complete).
    #[must_use]
    pub fn is_successful(&self) -> bool {
        matches!(self.state, DepartureState::Committed)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config() -> DepartureInitiatorConfig {
        DepartureInitiatorConfig {
            response_timeout: Duration::from_secs(5),
            quorum_timeout: Duration::from_secs(10),
        }
    }

    fn make_accept_response(peer_id: u64, successor_epoch: u64) -> DepartureResponse {
        DepartureResponse {
            peer_id,
            accepted: true,
            successor_epoch,
            reject_reason: None,
        }
    }

    fn make_reject_response(peer_id: u64, reason: &str) -> DepartureResponse {
        DepartureResponse {
            peer_id,
            accepted: false,
            successor_epoch: 0,
            reject_reason: Some(reason.into()),
        }
    }

    // ── Initiation ──────────────────────────────────────────────────

    #[test]
    fn initiate_sets_pending_state() {
        let init = DepartureInitiator::initiate(42, 7, 100, make_config());
        assert_eq!(init.state, DepartureState::Pending);
        assert_eq!(init.peer_id, 42);
        assert_eq!(init.reason, DepartureReason::Voluntary);
        assert_eq!(init.request_epoch, 7);
        assert_eq!(init.nonce, 100);
        assert!(init.request_sent_at.is_some());
    }

    #[test]
    fn build_request_produces_correct_fields() {
        let init = DepartureInitiator::initiate(42, 7, 100, make_config());
        let req = init.build_request();
        assert_eq!(req.peer_id, 42);
        assert_eq!(req.reason, DepartureReason::Voluntary);
        assert_eq!(req.request_epoch, 7);
        assert_eq!(req.nonce, 100);
    }

    // ── Response handling ───────────────────────────────────────────

    #[test]
    fn on_response_accepted_transitions_to_quorum_voting() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        let resp = make_accept_response(42, 8);
        init.on_response(&resp).unwrap();
        assert_eq!(init.state, DepartureState::QuorumVoting);
        assert!(init.quorum_started_at.is_some());
    }

    #[test]
    fn on_response_rejected_transitions_to_aborted() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        let resp = make_reject_response(42, "not in roster");
        init.on_response(&resp).unwrap();
        assert_eq!(init.state, DepartureState::Aborted);
        assert_eq!(init.rejection_reason.as_deref(), Some("not in roster"));
    }

    #[test]
    fn on_response_wrong_state_errors() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        // Accept response moves to QuorumVoting
        init.on_response(&make_accept_response(42, 8)).unwrap();
        // Second response should fail
        let err = init.on_response(&make_accept_response(42, 9)).unwrap_err();
        assert_eq!(
            err,
            InitiatorError::InvalidState {
                current: DepartureState::QuorumVoting,
                expected: "Pending"
            }
        );
    }

    // ── Epoch advancement ───────────────────────────────────────────

    #[test]
    fn on_epoch_advance_removes_peer_from_set() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_accept_response(42, 8)).unwrap();
        // New epoch has members [1, 3] — peer 42 is not in it.
        init.on_epoch_advance(8, &[1, 3]).unwrap();
        assert_eq!(init.state, DepartureState::Committed);
        assert_eq!(init.successor_epoch, Some(8));
    }

    #[test]
    fn on_epoch_advance_peer_still_in_set_does_not_commit() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_accept_response(42, 8)).unwrap();
        // Peer 42 is still in the member set — not yet removed.
        init.on_epoch_advance(8, &[1, 42, 3]).unwrap();
        assert_eq!(init.state, DepartureState::QuorumVoting);
        assert!(init.successor_epoch.is_none());
    }

    #[test]
    fn on_epoch_advance_wrong_state_errors() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        // Still Pending — epoch advance before response is invalid.
        let err = init.on_epoch_advance(8, &[1, 3]).unwrap_err();
        assert_eq!(
            err,
            InitiatorError::InvalidState {
                current: DepartureState::Pending,
                expected: "QuorumVoting"
            }
        );
    }

    #[test]
    fn on_epoch_advance_from_aborted_errors() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_reject_response(42, "nope")).unwrap();
        assert_eq!(init.state, DepartureState::Aborted);
        let err = init.on_epoch_advance(8, &[1, 3]).unwrap_err();
        assert_eq!(
            err,
            InitiatorError::InvalidState {
                current: DepartureState::Aborted,
                expected: "QuorumVoting"
            }
        );
    }

    // ── Drain complete ──────────────────────────────────────────────

    #[test]
    fn drain_complete_from_committed_succeeds() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_accept_response(42, 8)).unwrap();
        init.on_epoch_advance(8, &[1, 3]).unwrap();
        assert_eq!(init.state, DepartureState::Committed);
        init.drain_complete().unwrap();
        // State stays Committed (terminal), drain_complete is a noop success.
        assert!(init.is_terminal());
        assert!(init.is_successful());
    }

    #[test]
    fn drain_complete_wrong_state_errors() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        let err = init.drain_complete().unwrap_err();
        assert_eq!(
            err,
            InitiatorError::InvalidState {
                current: DepartureState::Pending,
                expected: "Committed"
            }
        );
    }

    // ── Timeout ─────────────────────────────────────────────────────

    #[test]
    fn timeout_in_pending_aborts() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        // Simulate a sent time far in the past
        init.request_sent_at = Some(Instant::now() - Duration::from_secs(10));
        let timed_out = init.check_timeout(Instant::now());
        assert!(timed_out);
        assert_eq!(init.state, DepartureState::Aborted);
        assert!(init
            .rejection_reason
            .as_deref()
            .unwrap()
            .contains("timeout"));
    }

    #[test]
    fn timeout_in_quorum_voting_aborts() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_accept_response(42, 8)).unwrap();
        init.quorum_started_at = Some(Instant::now() - Duration::from_secs(15));
        let timed_out = init.check_timeout(Instant::now());
        assert!(timed_out);
        assert_eq!(init.state, DepartureState::Aborted);
        assert!(init.rejection_reason.as_deref().unwrap().contains("quorum"));
    }

    #[test]
    fn no_timeout_when_within_limits() {
        let init = DepartureInitiator::initiate(42, 7, 100, make_config());
        let mut init2 = init.clone();
        let timed_out = init2.check_timeout(Instant::now());
        assert!(!timed_out);
        assert_eq!(init2.state, DepartureState::Pending);
    }

    #[test]
    fn no_timeout_in_terminal_state() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_reject_response(42, "nope")).unwrap();
        assert_eq!(init.state, DepartureState::Aborted);
        let timed_out = init.check_timeout(Instant::now());
        assert!(!timed_out);
    }

    // ── Terminal checks ─────────────────────────────────────────────

    #[test]
    fn is_terminal_when_committed() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_accept_response(42, 8)).unwrap();
        init.on_epoch_advance(8, &[1, 3]).unwrap();
        assert!(init.is_terminal());
        assert!(init.is_successful());
    }

    #[test]
    fn is_terminal_when_aborted() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        init.on_response(&make_reject_response(42, "nope")).unwrap();
        assert!(init.is_terminal());
        assert!(!init.is_successful());
    }

    #[test]
    fn not_terminal_when_pending() {
        let init = DepartureInitiator::initiate(42, 7, 100, make_config());
        assert!(!init.is_terminal());
        assert!(!init.is_successful());
    }

    // ── Full happy-path lifecycle ───────────────────────────────────

    #[test]
    fn full_voluntary_departure_lifecycle() {
        let mut init = DepartureInitiator::initiate(42, 7, 100, make_config());
        assert_eq!(init.state, DepartureState::Pending);

        // Coordinator accepts
        init.on_response(&make_accept_response(42, 8)).unwrap();
        assert_eq!(init.state, DepartureState::QuorumVoting);

        // Epoch advances, peer removed
        init.on_epoch_advance(8, &[1, 3, 5]).unwrap();
        assert_eq!(init.state, DepartureState::Committed);
        assert_eq!(init.successor_epoch, Some(8));

        // Drain completes
        init.drain_complete().unwrap();
        assert!(init.is_terminal());
        assert!(init.is_successful());
    }
}
