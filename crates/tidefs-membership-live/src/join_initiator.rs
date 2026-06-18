// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Joining-peer join request initiation and response handling state machine.
//!
//! Drives the joining peer's side of the membership join handshake. The
//! state machine is pure logic with no I/O: callers feed events (transport
//! connection, response arrival, timeout, disconnect) and the state machine
//! transitions, returning actions the caller must execute.
//!
//! ## States
//!
//! ```text
//! Idle ──► Connecting ──► RequestSent ──► Accepted ──► Active
//!   ▲          │                │              │
//!   │          │ (timeout or    │ (reject      │
//!   │          │  disconnect)   │  with retry) │
//!   └──────────┴────────────────┴──────────────┘
//!                Rejected (retries exhausted)
//! ```
//!
//! ## Integration
//!
//! The coordinator side is covered by #6182 (join-request validation), #6147
//! (join-response dispatch), and #6175 (coordinator crash-recovery journal).
//! This module consumes [`JoinOutcome`] to process accept/reject responses
//! and installs the assigned [`MemberId`], [`EpochId`], and roster into the
//! local [`MembershipRoster`].

use std::time::{SystemTime, UNIX_EPOCH};

use tidefs_membership_epoch::{EpochId, MemberId};

use crate::join_response::JoinOutcome;
use crate::roster::MembershipRoster;

// ── millis helper ──────────────────────────────────────────────────────

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

// ── JoinInitiatorState ──────────────────────────────────────────────────

/// States of the joining peer's join handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JoinInitiatorState {
    /// No join in progress. Ready to initiate.
    Idle,
    /// Establishing a transport session to the coordinator.
    Connecting,
    /// JoinRequest dispatched, awaiting a response.
    RequestSent,
    /// JoinResponse::Accepted received; roster installation pending.
    Accepted,
    /// Join was permanently rejected (retries exhausted or fatal rejection).
    Rejected,
    /// Roster installed and local member is operational.
    Active,
}

impl JoinInitiatorState {
    /// Whether the initiator is in a terminal state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Rejected | Self::Active)
    }

    /// Whether a new join can be initiated from this state.
    pub fn can_initiate(self) -> bool {
        matches!(self, Self::Idle)
    }
}

// ── JoinInitiatorConfig ─────────────────────────────────────────────────

/// Configuration for the join initiator state machine.
#[derive(Clone, Debug)]
pub struct JoinInitiatorConfig {
    /// The target coordinator's member ID.
    pub coordinator_member_id: MemberId,
    /// Maximum time (milliseconds) to wait for a JoinResponse after dispatch.
    pub request_timeout_ms: u64,
    /// Maximum number of join retries before permanent failure.
    pub max_retries: u32,
    /// Base backoff duration (milliseconds) for exponential retry.
    pub backoff_base_ms: u64,
}

impl Default for JoinInitiatorConfig {
    fn default() -> Self {
        Self {
            coordinator_member_id: MemberId::new(0),
            request_timeout_ms: 15_000,
            max_retries: 5,
            backoff_base_ms: 1_000,
        }
    }
}

// ── JoinResult ──────────────────────────────────────────────────────────

/// Outcome of a join initiation or event-sink call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JoinResult {
    /// Join is in progress; caller should wait for the next event.
    InProgress,
    /// Join was accepted. Caller should install the roster.
    ///
    /// The assigned `MemberId`, `EpochId`, and roster member set are included.
    Accepted {
        member_id: MemberId,
        epoch: EpochId,
        /// Sorted list of member IDs in the roster after join.
        roster: Vec<MemberId>,
    },
    /// Join was permanently rejected.
    Rejected {
        reason: String,
        /// Whether the retry budget is exhausted.
        retries_exhausted: bool,
    },
    /// The initiator transitioned to Active after roster installation.
    Active,
}

// ── JoinInitiator ───────────────────────────────────────────────────────

/// State machine driving the joining peer's side of the membership join
/// protocol.
///
/// # Lifecycle
///
/// 1. Create with [`JoinInitiator::new`].
/// 2. Call [`initiate`] to transition to `Connecting` and obtain the
///    coordinator MemberId to connect to.
/// 3. After transport connection is established, call [`on_connected`] to
///    transition to `RequestSent`. The returned [`JoinRequest`] data must be
///    serialized and dispatched over transport.
/// 4. On receiving a [`JoinOutcome`] over transport, call [`on_response`].
///    - `Accepted` → stores the assigned identity and transitions to
///      `Accepted`. Call [`install_roster`] to write the roster and advance
///      to `Active`.
///    - `Rejected` → backoff/retry if budget remains, or permanent
///      `Rejected`.
/// 5. On timeout (no response within `request_timeout_ms`), call
///    [`on_timeout`].
/// 6. On transport disconnect during handshake, call [`on_disconnect`].
///
/// # Retry
///
/// Exponential backoff: the delay before retrying is
/// `backoff_base_ms * 2^retry_attempt` clamped to `request_timeout_ms`.
///
/// [`initiate`]: Self::initiate
/// [`on_connected`]: Self::on_connected
/// [`install_roster`]: Self::install_roster
/// [`on_response`]: Self::on_response
/// [`on_timeout`]: Self::on_timeout
/// [`on_disconnect`]: Self::on_disconnect
pub struct JoinInitiator {
    /// Current state.
    state: JoinInitiatorState,
    /// Configuration (immutable after construction).
    config: JoinInitiatorConfig,
    /// Member ID assigned by the coordinator on acceptance.
    assigned_member_id: Option<MemberId>,
    /// Epoch at which the join was accepted.
    assigned_epoch: Option<EpochId>,
    /// Roster member set received on acceptance.
    accepted_roster: Vec<MemberId>,
    /// Number of retries attempted so far.
    retry_count: u32,
    /// Millisecond timestamp when the join was initiated.
    initiated_at_ms: u64,
    /// Millisecond timestamp when the request was sent.
    request_sent_at_ms: u64,
    /// Millisecond timestamp when the join was accepted.
    accepted_at_ms: u64,
    /// Reason for permanent rejection.
    rejection_reason: Option<String>,
    /// Whether the retry budget has been exhausted.
    retries_exhausted: bool,
}

impl JoinInitiator {
    /// Create a new join initiator in the `Idle` state.
    pub fn new(config: JoinInitiatorConfig) -> Self {
        Self {
            state: JoinInitiatorState::Idle,
            config,
            assigned_member_id: None,
            assigned_epoch: None,
            accepted_roster: Vec::new(),
            retry_count: 0,
            initiated_at_ms: 0,
            request_sent_at_ms: 0,
            accepted_at_ms: 0,
            rejection_reason: None,
            retries_exhausted: false,
        }
    }

    // ── Accessors ──────────────────────────────────────────────────────

    /// Current state.
    pub fn state(&self) -> JoinInitiatorState {
        self.state
    }

    /// The coordinator member ID this initiator targets.
    pub fn coordinator_member_id(&self) -> MemberId {
        self.config.coordinator_member_id
    }

    /// The member ID assigned by the coordinator (only set after acceptance).
    pub fn assigned_member_id(&self) -> Option<MemberId> {
        self.assigned_member_id
    }

    /// The epoch at which the join was accepted.
    pub fn assigned_epoch(&self) -> Option<EpochId> {
        self.assigned_epoch
    }

    /// Number of retries attempted so far.
    pub fn retry_count(&self) -> u32 {
        self.retry_count
    }

    /// Whether the retry budget has been exhausted.
    pub fn is_retries_exhausted(&self) -> bool {
        self.retries_exhausted
    }

    /// Millisecond timestamp when the join was initiated.
    pub fn initiated_at_ms(&self) -> u64 {
        self.initiated_at_ms
    }

    /// Reason for rejection, if in `Rejected` state.
    pub fn rejection_reason(&self) -> Option<&str> {
        self.rejection_reason.as_deref()
    }

    // ── Transitions ────────────────────────────────────────────────────

    /// Initiate the join handshake.
    ///
    /// Transitions `Idle` → `Connecting`. The caller must establish a
    /// transport session to the coordinator and then call [`on_connected`].
    ///
    /// Returns the coordinator member ID to connect to and a
    /// [`JoinResult::InProgress`].
    ///
    /// # Errors
    ///
    /// Returns an error string if called from a non-`Idle` state (double-join
    /// prevention).
    pub fn initiate(&mut self) -> Result<JoinResult, String> {
        if self.state != JoinInitiatorState::Idle {
            return Err(format!(
                "cannot initiate join from {:?} state (must be Idle)",
                self.state,
            ));
        }

        self.state = JoinInitiatorState::Connecting;
        self.initiated_at_ms = now_millis();
        Ok(JoinResult::InProgress)
    }

    /// Signal that transport connection to the coordinator is established.
    ///
    /// Transitions `Connecting` → `RequestSent`. Returns a [`JoinResult`]
    /// indicating the caller should serialize and dispatch a
    /// `JoinRequest` message.
    ///
    /// # Errors
    ///
    /// Returns an error string if not in `Connecting` state.
    pub fn on_connected(&mut self) -> Result<JoinResult, String> {
        if self.state != JoinInitiatorState::Connecting {
            return Err(format!(
                "on_connected called from {:?} state (expected Connecting)",
                self.state,
            ));
        }

        self.state = JoinInitiatorState::RequestSent;
        self.request_sent_at_ms = now_millis();
        Ok(JoinResult::InProgress)
    }

    /// Process a join response received from the coordinator.
    ///
    /// - `Accepted` → transitions to `Accepted`, stores the assigned
    ///   MemberId, EpochId, and roster. Caller must then call
    ///   [`install_roster`] to write the roster and advance to `Active`.
    /// - `Rejected` → if retry budget remains, transitions back to `Idle`
    ///   for the caller to re-initiate (after backoff). If budget exhausted,
    ///   transitions to `Rejected` with `retries_exhausted: true`.
    ///
    /// # Errors
    ///
    /// Returns an error string if not in `RequestSent` state.
    pub fn on_response(&mut self, outcome: &JoinOutcome) -> Result<JoinResult, String> {
        if self.state != JoinInitiatorState::RequestSent {
            return Err(format!(
                "on_response called from {:?} state (expected RequestSent)",
                self.state,
            ));
        }

        match outcome {
            JoinOutcome::Accepted {
                member_id,
                epoch,
                roster,
                ..
            } => {
                self.state = JoinInitiatorState::Accepted;
                self.assigned_member_id = Some(*member_id);
                self.assigned_epoch = Some(*epoch);
                self.accepted_roster = roster.clone();
                self.accepted_at_ms = now_millis();
                Ok(JoinResult::Accepted {
                    member_id: *member_id,
                    epoch: *epoch,
                    roster: roster.clone(),
                })
            }
            JoinOutcome::Rejected { reason } => {
                self.retry_count += 1;
                if self.retry_count <= self.config.max_retries {
                    // Retry budget remains: reset to Idle for caller to
                    // re-initiate after backoff delay.
                    self.state = JoinInitiatorState::Idle;
                    Ok(JoinResult::Rejected {
                        reason: format!(
                            "{reason} (retry {current}/{max})",
                            current = self.retry_count,
                            max = self.config.max_retries,
                        ),
                        retries_exhausted: false,
                    })
                } else {
                    self.state = JoinInitiatorState::Rejected;
                    self.rejection_reason = Some(format!(
                        "{reason} (retries exhausted: {attempts}/{max})",
                        attempts = self.retry_count,
                        max = self.config.max_retries,
                    ));
                    self.retries_exhausted = true;
                    Ok(JoinResult::Rejected {
                        reason: self.rejection_reason.clone().unwrap(),
                        retries_exhausted: true,
                    })
                }
            }
        }
    }

    /// Handle a request timeout.
    ///
    /// If retry budget remains, transitions back to `Idle` for re-initiation.
    /// If budget exhausted, transitions to `Rejected`.
    ///
    /// # Errors
    ///
    /// Returns an error string if not in `RequestSent` state.
    pub fn on_timeout(&mut self) -> Result<JoinResult, String> {
        if self.state != JoinInitiatorState::RequestSent {
            return Err(format!(
                "on_timeout called from {:?} state (expected RequestSent)",
                self.state,
            ));
        }

        self.retry_count += 1;
        if self.retry_count <= self.config.max_retries {
            self.state = JoinInitiatorState::Idle;
            Ok(JoinResult::Rejected {
                reason: format!(
                    "request timeout (retry {current}/{max})",
                    current = self.retry_count,
                    max = self.config.max_retries,
                ),
                retries_exhausted: false,
            })
        } else {
            self.state = JoinInitiatorState::Rejected;
            self.rejection_reason = Some(format!(
                "request timeout (retries exhausted: {attempts}/{max})",
                attempts = self.retry_count,
                max = self.config.max_retries,
            ));
            self.retries_exhausted = true;
            Ok(JoinResult::Rejected {
                reason: self.rejection_reason.clone().unwrap(),
                retries_exhausted: true,
            })
        }
    }

    /// Handle transport disconnect during the handshake.
    ///
    /// Transitions `Connecting` or `RequestSent` back to `Idle` for retry,
    /// or to `Rejected` if the retry budget is exhausted.
    ///
    /// # Errors
    ///
    /// Returns an error string if called from `Accepted`, `Rejected`, or
    /// `Active` state (disconnect is irrelevant there).
    pub fn on_disconnect(&mut self) -> Result<JoinResult, String> {
        match self.state {
            JoinInitiatorState::Connecting | JoinInitiatorState::RequestSent => {
                self.retry_count += 1;
                if self.retry_count <= self.config.max_retries {
                    self.state = JoinInitiatorState::Idle;
                    Ok(JoinResult::Rejected {
                        reason: format!(
                            "transport disconnect (retry {current}/{max})",
                            current = self.retry_count,
                            max = self.config.max_retries,
                        ),
                        retries_exhausted: false,
                    })
                } else {
                    self.state = JoinInitiatorState::Rejected;
                    self.rejection_reason = Some(format!(
                        "transport disconnect (retries exhausted: {attempts}/{max})",
                        attempts = self.retry_count,
                        max = self.config.max_retries,
                    ));
                    self.retries_exhausted = true;
                    Ok(JoinResult::Rejected {
                        reason: self.rejection_reason.clone().unwrap(),
                        retries_exhausted: true,
                    })
                }
            }
            JoinInitiatorState::Idle => {
                // Idempotent: disconnect before initiating is a no-op.
                Ok(JoinResult::InProgress)
            }
            _ => Err(format!(
                "on_disconnect called from {:?} state (not recoverable)",
                self.state,
            )),
        }
    }

    /// Install the accepted roster into the local [`MembershipRoster`] and
    /// transition to `Active`.
    ///
    /// Adds all members from the accepted roster to the roster, then marks
    /// the join as complete by transitioning to `Active`.
    ///
    /// # Errors
    ///
    /// Returns an error string if not in `Accepted` state, or if the local
    /// roster cannot be written (roster mutation error).
    pub fn install_roster(&mut self, roster: &mut MembershipRoster) -> Result<JoinResult, String> {
        if self.state != JoinInitiatorState::Accepted {
            return Err(format!(
                "install_roster called from {:?} state (expected Accepted)",
                self.state,
            ));
        }

        // Ensure we have an assigned member ID.
        let local_id = self.assigned_member_id.ok_or_else(|| {
            "install_roster: no assigned member ID (acceptance incomplete)".to_string()
        })?;

        // Add all members from the accepted roster.
        for &member_id in &self.accepted_roster {
            roster.add_member(member_id);
        }

        // Verify the local member is now in the roster.
        let _state = roster.snapshot().lookup(local_id).ok_or_else(|| {
            format!(
                "install_roster: assigned member {local_id} not found in roster after installation",
                local_id = local_id.0,
            )
        })?;

        self.state = JoinInitiatorState::Active;
        Ok(JoinResult::Active)
    }

    /// Compute the backoff delay before the next retry.
    ///
    /// Uses exponential backoff: `backoff_base_ms * 2^retry_attempt`,
    /// clamped to `request_timeout_ms`.
    pub fn backoff_delay_ms(&self) -> u64 {
        let attempt = self.retry_count.min(10); // clamp exponent to avoid overflow
        let raw = self.config.backoff_base_ms * (1u64 << attempt);
        raw.min(self.config.request_timeout_ms)
    }

    /// Check whether the current request has timed out.
    ///
    /// Returns `true` if the initiator is in `RequestSent` state and the
    /// configured deadline has elapsed.
    pub fn is_timed_out(&self, now_ms: u64) -> bool {
        if self.state != JoinInitiatorState::RequestSent {
            return false;
        }
        now_ms.saturating_sub(self.request_sent_at_ms) > self.config.request_timeout_ms
    }

    /// Reset the initiator back to `Idle`, clearing all state.
    ///
    /// Useful for testing or manual re-initialization.
    pub fn reset(&mut self) {
        self.state = JoinInitiatorState::Idle;
        self.assigned_member_id = None;
        self.assigned_epoch = None;
        self.accepted_roster.clear();
        self.retry_count = 0;
        self.initiated_at_ms = 0;
        self.request_sent_at_ms = 0;
        self.accepted_at_ms = 0;
        self.rejection_reason = None;
        self.retries_exhausted = false;
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_membership_epoch::Incarnation;

    // Helper: create a test config.
    fn test_config() -> JoinInitiatorConfig {
        JoinInitiatorConfig {
            coordinator_member_id: MemberId::new(1),
            request_timeout_ms: 5_000,
            max_retries: 3,
            backoff_base_ms: 100,
        }
    }

    fn test_accepted() -> JoinOutcome {
        JoinOutcome::Accepted {
            incarnation: Incarnation::ZERO,
            member_id: MemberId::new(42),
            epoch: EpochId::new(7),
            roster: vec![MemberId::new(1), MemberId::new(42)],
        }
    }

    fn test_rejected(reason: &str) -> JoinOutcome {
        JoinOutcome::Rejected {
            reason: reason.to_string(),
        }
    }

    // ── Construction and initial state ──

    #[test]
    fn new_starts_idle() {
        let j = JoinInitiator::new(test_config());
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert!(!j.is_retries_exhausted());
        assert_eq!(j.retry_count(), 0);
        assert!(j.rejection_reason().is_none());
        assert!(j.assigned_member_id().is_none());
    }

    #[test]
    fn default_config_values() {
        let cfg = JoinInitiatorConfig::default();
        assert_eq!(cfg.request_timeout_ms, 15_000);
        assert_eq!(cfg.max_retries, 5);
        assert_eq!(cfg.backoff_base_ms, 1_000);
    }

    // ── Initiate ──

    #[test]
    fn initiate_from_idle_goes_to_connecting() {
        let mut j = JoinInitiator::new(test_config());
        let result = j.initiate().unwrap();
        assert_eq!(result, JoinResult::InProgress);
        assert_eq!(j.state(), JoinInitiatorState::Connecting);
        assert!(j.initiated_at_ms() > 0);
    }

    #[test]
    fn initiate_from_non_idle_errors() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap(); // Idle → Connecting
        j.on_connected().unwrap(); // Connecting → RequestSent

        let err = j.initiate().unwrap_err();
        assert!(
            err.contains("RequestSent"),
            "expected error mentioning state: {err}"
        );
    }

    #[test]
    fn initiate_from_rejected_is_not_allowed() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            max_retries: 0,
            ..test_config()
        });
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let _ = j.on_response(&test_rejected("full")).unwrap();

        assert_eq!(j.state(), JoinInitiatorState::Rejected);
        let err = j.initiate().unwrap_err();
        assert!(err.contains("Rejected"));
    }

    // ── on_connected ──

    #[test]
    fn on_connected_from_connecting_goes_to_request_sent() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        let result = j.on_connected().unwrap();
        assert_eq!(result, JoinResult::InProgress);
        assert_eq!(j.state(), JoinInitiatorState::RequestSent);
        assert!(j.request_sent_at_ms > 0);
    }

    #[test]
    fn on_connected_from_idle_errors() {
        let mut j = JoinInitiator::new(test_config());
        let err = j.on_connected().unwrap_err();
        assert!(err.contains("Idle"));
    }

    #[test]
    fn on_connected_twice_errors() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let err = j.on_connected().unwrap_err();
        assert!(err.contains("RequestSent"));
    }

    // ── on_response: accepted ──

    #[test]
    fn on_response_accepted_transitions_to_accepted() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        let result = j.on_response(&test_accepted()).unwrap();
        assert_eq!(
            result,
            JoinResult::Accepted {
                member_id: MemberId::new(42),
                epoch: EpochId::new(7),
                roster: vec![MemberId::new(1), MemberId::new(42)],
            }
        );
        assert_eq!(j.state(), JoinInitiatorState::Accepted);
        assert_eq!(j.assigned_member_id(), Some(MemberId::new(42)));
        assert_eq!(j.assigned_epoch(), Some(EpochId::new(7)));
        assert!(j.accepted_at_ms > 0);
    }

    #[test]
    fn on_response_accepted_from_wrong_state_errors() {
        let mut j = JoinInitiator::new(test_config());
        let err = j.on_response(&test_accepted()).unwrap_err();
        assert!(err.contains("Idle"));
    }

    // ── install_roster ──

    #[test]
    fn install_roster_transitions_to_active() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_accepted()).unwrap();

        let mut roster = MembershipRoster::new();
        let result = j.install_roster(&mut roster).unwrap();
        assert_eq!(result, JoinResult::Active);
        assert_eq!(j.state(), JoinInitiatorState::Active);

        // Verify roster contains both members.
        let snap = roster.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.lookup(MemberId::new(1)).is_some());
        assert!(snap.lookup(MemberId::new(42)).is_some());
    }

    #[test]
    fn install_roster_from_wrong_state_errors() {
        let mut j = JoinInitiator::new(test_config());
        let mut roster = MembershipRoster::new();
        let err = j.install_roster(&mut roster).unwrap_err();
        assert!(err.contains("Idle"));
    }

    #[test]
    fn install_roster_without_assigned_member_id_errors() {
        let mut j = JoinInitiator::new(test_config());
        // Force Accepted state without member id (simulate edge case).
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_accepted()).unwrap();
        j.assigned_member_id = None;

        let mut roster = MembershipRoster::new();
        let err = j.install_roster(&mut roster).unwrap_err();
        assert!(err.contains("no assigned member ID"));
    }

    // ── on_response: rejected with retry ──

    #[test]
    fn on_response_rejected_with_retries_returns_to_idle() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        let result = j.on_response(&test_rejected("capacity")).unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if !retries_exhausted),
            "expected non-exhausted rejection, got {result:?}"
        );
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 1);
    }

    #[test]
    fn on_response_rejected_exhausts_retries() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            max_retries: 1,
            ..test_config()
        });

        // First attempt: rejected, retries left.
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let _result = j.on_response(&test_rejected("capacity")).unwrap();
        assert!(!j.is_retries_exhausted());
        assert_eq!(j.state(), JoinInitiatorState::Idle);

        // Second attempt: rejected, no retries left.
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let result = j.on_response(&test_rejected("still full")).unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if *retries_exhausted),
            "expected exhausted rejection, got {result:?}"
        );
        assert_eq!(j.state(), JoinInitiatorState::Rejected);
        assert!(j.is_retries_exhausted());
        assert_eq!(j.retry_count(), 2);
        assert!(j.rejection_reason().unwrap().contains("still full"));
    }

    #[test]
    fn on_response_rejected_with_zero_max_retries() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            max_retries: 0,
            ..test_config()
        });
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let result = j.on_response(&test_rejected("no")).unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if *retries_exhausted),
        );
        assert!(j.is_retries_exhausted());
    }

    // ── on_timeout ──

    #[test]
    fn on_timeout_with_retries_returns_to_idle() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        let result = j.on_timeout().unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if !retries_exhausted),
        );
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 1);
    }

    #[test]
    fn on_timeout_exhausts_retries() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            max_retries: 2,
            ..test_config()
        });

        // First timeout
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_timeout().unwrap();
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 1);

        // Second timeout
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_timeout().unwrap();
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 2);

        // Third timeout (exhausted)
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let result = j.on_timeout().unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if *retries_exhausted),
        );
        assert_eq!(j.state(), JoinInitiatorState::Rejected);
        assert!(j.is_retries_exhausted());
    }

    #[test]
    fn on_timeout_from_wrong_state_errors() {
        let mut j = JoinInitiator::new(test_config());
        let err = j.on_timeout().unwrap_err();
        assert!(err.contains("Idle"));
    }

    // ── is_timed_out ──

    #[test]
    fn is_timed_out_returns_false_after_elapse_within_window() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        let sent_at = j.request_sent_at_ms;
        // Within window.
        assert!(!j.is_timed_out(sent_at + 4_000));
    }

    #[test]
    fn is_timed_out_returns_true_after_deadline() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        let sent_at = j.request_sent_at_ms;
        // Exactly at boundary: 5000 <= 5000 is not "> timeout".
        assert!(!j.is_timed_out(sent_at + 5_000));
        // Past boundary.
        assert!(j.is_timed_out(sent_at + 5_001));
    }

    #[test]
    fn is_timed_out_returns_false_when_not_request_sent() {
        let mut j = JoinInitiator::new(test_config());
        assert!(!j.is_timed_out(99_999));
        j.initiate().unwrap();
        assert!(!j.is_timed_out(99_999));
    }

    // ── on_disconnect ──

    #[test]
    fn on_disconnect_from_connecting_with_retries() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        let result = j.on_disconnect().unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if !retries_exhausted),
        );
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 1);
    }

    #[test]
    fn on_disconnect_from_request_sent_with_retries() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let result = j.on_disconnect().unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if !retries_exhausted),
        );
        assert_eq!(j.state(), JoinInitiatorState::Idle);
    }

    #[test]
    fn on_disconnect_exhausts_retries() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            max_retries: 0,
            ..test_config()
        });
        j.initiate().unwrap();
        let result = j.on_disconnect().unwrap();
        assert!(
            matches!(&result, JoinResult::Rejected { retries_exhausted, .. } if *retries_exhausted),
        );
        assert_eq!(j.state(), JoinInitiatorState::Rejected);
    }

    #[test]
    fn on_disconnect_from_idle_is_noop() {
        let mut j = JoinInitiator::new(test_config());
        let result = j.on_disconnect().unwrap();
        assert_eq!(result, JoinResult::InProgress);
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 0);
    }

    #[test]
    fn on_disconnect_from_accepted_errors() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_accepted()).unwrap();
        let err = j.on_disconnect().unwrap_err();
        assert!(err.contains("Accepted"));
    }

    #[test]
    fn on_disconnect_from_active_errors() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_accepted()).unwrap();
        let mut roster = MembershipRoster::new();
        j.install_roster(&mut roster).unwrap();

        let err = j.on_disconnect().unwrap_err();
        assert!(err.contains("Active"));
    }

    // ── backoff_delay_ms ──

    #[test]
    fn backoff_delay_increases_exponentially() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();

        // retry_count = 0 initially, but after first reject it's 1.
        j.on_response(&test_rejected("a")).unwrap();
        assert_eq!(j.retry_count(), 1);
        let delay1 = j.backoff_delay_ms(); // 100 * 2^1 = 200

        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_rejected("b")).unwrap();
        assert_eq!(j.retry_count(), 2);
        let delay2 = j.backoff_delay_ms(); // 100 * 2^2 = 400

        assert_eq!(delay1, 200);
        assert_eq!(delay2, 400);
    }

    #[test]
    fn backoff_delay_clamped_to_timeout() {
        let mut j = JoinInitiator::new(JoinInitiatorConfig {
            request_timeout_ms: 1_000,
            ..test_config()
        });
        // Force a high retry count.
        j.retry_count = 20;
        let delay = j.backoff_delay_ms();
        assert_eq!(delay, 1_000); // clamped
    }

    // ── reset ──

    #[test]
    fn reset_clears_everything() {
        let mut j = JoinInitiator::new(test_config());
        j.initiate().unwrap();
        j.on_connected().unwrap();
        j.on_response(&test_accepted()).unwrap();

        j.reset();
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 0);
        assert!(!j.is_retries_exhausted());
        assert!(j.assigned_member_id().is_none());
        assert!(j.rejection_reason().is_none());
    }

    // ── Full lifecycle: success ──

    #[test]
    fn full_lifecycle_success_path() {
        let mut j = JoinInitiator::new(test_config());

        // 1. Idle → Connecting
        let r = j.initiate().unwrap();
        assert_eq!(r, JoinResult::InProgress);
        assert_eq!(j.state(), JoinInitiatorState::Connecting);

        // 2. Connecting → RequestSent
        let r = j.on_connected().unwrap();
        assert_eq!(r, JoinResult::InProgress);
        assert_eq!(j.state(), JoinInitiatorState::RequestSent);

        // 3. RequestSent → Accepted (response received)
        let outcome = JoinOutcome::Accepted {
            incarnation: Incarnation::ZERO,
            member_id: MemberId::new(42),
            epoch: EpochId::new(7),
            roster: vec![MemberId::new(1), MemberId::new(42), MemberId::new(99)],
        };
        let r = j.on_response(&outcome).unwrap();
        assert!(matches!(r, JoinResult::Accepted { .. }));
        assert_eq!(j.state(), JoinInitiatorState::Accepted);
        assert_eq!(j.assigned_member_id(), Some(MemberId::new(42)));
        assert_eq!(j.assigned_epoch(), Some(EpochId::new(7)));

        // 4. Accepted → Active (roster installed)
        let mut roster = MembershipRoster::new();
        let r = j.install_roster(&mut roster).unwrap();
        assert_eq!(r, JoinResult::Active);
        assert_eq!(j.state(), JoinInitiatorState::Active);

        let snap = roster.snapshot();
        assert_eq!(snap.len(), 3);
        assert!(snap.lookup(MemberId::new(42)).is_some());
    }

    // ── Full lifecycle: retry then success ──

    #[test]
    fn full_lifecycle_retry_then_success() {
        let mut j = JoinInitiator::new(test_config());

        // First attempt: rejected.
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let r = j.on_response(&test_rejected("try again")).unwrap();
        assert!(matches!(&r, JoinResult::Rejected { retries_exhausted, .. } if !retries_exhausted),);
        assert_eq!(j.state(), JoinInitiatorState::Idle);
        assert_eq!(j.retry_count(), 1);

        // Second attempt: accepted.
        j.initiate().unwrap();
        j.on_connected().unwrap();
        let r = j.on_response(&test_accepted()).unwrap();
        assert!(matches!(r, JoinResult::Accepted { .. }));
        assert_eq!(j.state(), JoinInitiatorState::Accepted);

        let mut roster = MembershipRoster::new();
        j.install_roster(&mut roster).unwrap();
        assert_eq!(j.state(), JoinInitiatorState::Active);
    }

    // ── Terminals ──

    #[test]
    fn terminal_states() {
        assert!(!JoinInitiatorState::Idle.is_terminal());
        assert!(!JoinInitiatorState::Connecting.is_terminal());
        assert!(!JoinInitiatorState::RequestSent.is_terminal());
        assert!(!JoinInitiatorState::Accepted.is_terminal());
        assert!(JoinInitiatorState::Rejected.is_terminal());
        assert!(JoinInitiatorState::Active.is_terminal());
    }

    #[test]
    fn can_initiate() {
        assert!(JoinInitiatorState::Idle.can_initiate());
        assert!(!JoinInitiatorState::Connecting.can_initiate());
        assert!(!JoinInitiatorState::RequestSent.can_initiate());
        assert!(!JoinInitiatorState::Accepted.can_initiate());
        assert!(!JoinInitiatorState::Rejected.can_initiate());
        assert!(!JoinInitiatorState::Active.can_initiate());
    }
}
