// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Reconnection state machine — preserves endpoint invariants across connection drops.
//!
//! ## Reconnection and the endpoint lifecycle
//!
//! Reconnection is the mechanism that allows a [`Session`](crate::session::Session)
//! to survive transient network failures without losing its bound state.
//! The [`ReconnectState`] and [`ReconnectPolicy`] govern how a session
//! retries after a connection drop.
//!
//! ### Endpoint invariants preserved during reconnection
//!
//! Every reconnect attempt preserves the session's original endpoint binding:
//!
//! - **family-stable** — the [`EndpointFamily`](tidefs_types_transport_session::EndpointFamily)
//!   is set once during [`Session::new()`](crate::session::Session::new) and
//!   never changes, even across reconnection cycles. A session on a `Data`
//!   endpoint reconnects on `Data`, not `Control`.
//! - **identity-stable** — the local and peer node identities are preserved
//!   across reconnection. A new mutual attestation handshake is performed on
//!   each reconnect to re-verify identities.
//! - **cohort-stable** — cohort attachments survive reconnection. The
//!   reconnected session resumes with the same cohort graph membership.
//! - **lane-stable** — lane budgets and demux state are preserved across
//!   reconnection. Buffered data is retained until the session is drained
//!   or closed.
//!
//! ### Reconnection state machine
//!
//! The [`ReconnectState`] tracks retry attempts with backoff:
//!
//! 1. **Initial state** — `attempt = 0`, `current_backoff` set by policy.
//! 2. **Failed attempt** — `next_backoff()` increments the counter and
//!    computes the next wait duration.
//! 3. **Exhausted** — when `attempt >= max_attempts`, reconnection is
//!    abandoned and the session transitions to `Closed`.
//! 4. **Success** — `reset()` clears the counter and restores the initial
//!    backoff, ready for the next cycle.
//!
//! ### Session state transitions during reconnection
//!
//! When a connection drops, the session state machine follows this path:
//!
//! ```text
//! Established → Degraded → Reconnecting → Connecting → Handshaking → Established
//! ```
//!
//! If reconnection fails and `is_exhausted()` returns true, the terminal path is:
//!
//! ```text
//! Reconnecting → Closed
//! ```
//!
//! ### Backoff policies
//!
//! | Policy | Behavior | Use case |
//! |---|---|---|
//! | `ExponentialBackoff` | Doubles backoff each attempt (default: 100 ms → 200 ms → 400 ms … capped at 30 s) | Transient failures (network flaps) |
//! | `FixedInterval` | Same backoff every attempt | Predictable retry cadence (e.g., test harnesses) |
//!
use crate::types::SessionId;
use rand::Rng;
use std::fmt;
use std::time::Duration;
use std::time::Instant;
pub use tidefs_types_transport_session::MessageSequenceNumber;

// ---------------------------------------------------------------------------
// Reconnection state and policy
// ---------------------------------------------------------------------------

/// Reconnection state machine with exponential backoff.
/// Reconnection state machine with exponential backoff.
pub struct ReconnectState {
    /// Current retry attempt counter (0 = no attempt yet).
    pub attempt: u32,
    /// Maximum retries before giving up (default 10).
    pub max_attempts: u32,
    /// Current backoff duration to wait before the next attempt.
    pub current_backoff: Duration,
    /// Backoff policy governing how the backoff duration evolves.
    pub policy: ReconnectPolicy,
}

impl ReconnectState {
    #[must_use]
    /// Create a new reconnect state machine with default exponential backoff.
    pub fn new() -> Self {
        Self {
            attempt: 0,
            max_attempts: 10,
            current_backoff: Duration::from_millis(100),
            policy: ReconnectPolicy::default(),
        }
    }

    #[must_use]
    /// Create a new reconnect state with the given policy.
    pub fn with_policy(policy: ReconnectPolicy) -> Self {
        let current_backoff = match &policy {
            ReconnectPolicy::ExponentialBackoff { initial, .. } => *initial,
            ReconnectPolicy::FixedInterval(d) => *d,
        };
        Self {
            attempt: 0,
            max_attempts: 10,
            current_backoff,
            policy,
        }
    }

    /// Compute the next backoff duration and increment attempt counter.
    #[must_use]
    pub fn next_backoff(&mut self) -> Duration {
        self.attempt += 1;
        match &self.policy {
            ReconnectPolicy::ExponentialBackoff {
                initial,
                max,
                multiplier_millis: _,
            } => {
                let factor = self.policy.multiplier_f64().powi(self.attempt as i32 - 1);
                let backoff = mul_duration_f64(*initial, factor);
                self.current_backoff = backoff.min(*max);
                self.current_backoff
            }
            ReconnectPolicy::FixedInterval(d) => {
                self.current_backoff = *d;
                *d
            }
        }
    }

    /// Whether reconnection attempts are exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.attempt >= self.max_attempts
    }

    /// Reset retry counter (e.g., after successful reconnection).
    pub fn reset(&mut self) {
        self.attempt = 0;
        match &self.policy {
            ReconnectPolicy::ExponentialBackoff { initial, .. } => {
                self.current_backoff = *initial;
            }
            ReconnectPolicy::FixedInterval(d) => {
                self.current_backoff = *d;
            }
        }
    }
}

impl Default for ReconnectState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Reconnection policy
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
/// Reconnection policy: exponential backoff or fixed interval.
pub enum ReconnectPolicy {
    /// Exponential backoff: each failed attempt doubles the backoff
    /// duration, starting at `initial` and capped at `max`.
    /// Default: 100 ms initial, 30 s max, 2.0× multiplier.
    ExponentialBackoff {
        /// Initial backoff duration.
        initial: Duration,
        /// Maximum backoff duration (cap).
        max: Duration,
        /// Multiplier as raw integer millis to avoid f64 Eq problem
        /// (e.g. 2000 means 2.0×).
        multiplier_millis: u64,
    },
    /// Fixed interval: every reconnection attempt waits exactly the
    /// same duration before retrying.
    FixedInterval(Duration),
}

impl ReconnectPolicy {
    /// Get the multiplier as f64 for backoff calculation.
    fn multiplier_f64(&self) -> f64 {
        match self {
            Self::ExponentialBackoff {
                multiplier_millis, ..
            } => {
                // Convert from millis-per-millis ratio: 2000 means 2.0x
                (*multiplier_millis as f64) / 1000.0
            }
            _ => 1.0,
        }
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::ExponentialBackoff {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(30),
            multiplier_millis: 2000, // 2.0x
        }
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
// ReconnectConfig -- unified reconnect configuration
// ---------------------------------------------------------------------------

/// Configuration for the session resumption reconnect protocol.
///
/// Aggregates all tunable parameters: retry budget, backoff bounds,
/// per-attempt timeout, and jitter.
#[derive(Clone, Debug, PartialEq)]
pub struct ReconnectConfig {
    /// Maximum number of reconnect attempts before giving up.
    pub max_retries: u32,
    /// Base backoff in milliseconds before the first retry.
    pub base_backoff_ms: u64,
    /// Hard cap on the backoff duration in milliseconds.
    pub max_backoff_ms: u64,
    /// Per-attempt timeout for the session resumption handshake.
    pub session_resumption_timeout_ms: u64,
    /// Jitter fraction (0.0–0.5). 0.2 means +/- 20% uniform jitter.
    pub jitter_factor: f64,
}

impl ReconnectConfig {
    /// Default configuration tuned for transient network failures.
    #[must_use]
    pub fn default_config() -> Self {
        Self {
            max_retries: 10,
            base_backoff_ms: 100,
            max_backoff_ms: 30_000,
            session_resumption_timeout_ms: 5_000,
            jitter_factor: 0.2,
        }
    }

    /// Validate configuration values.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_retries == 0 {
            return Err("max_retries must be greater than 0");
        }
        if self.base_backoff_ms == 0 {
            return Err("base_backoff_ms must be greater than 0");
        }
        if self.max_backoff_ms < self.base_backoff_ms {
            return Err("max_backoff_ms must be >= base_backoff_ms");
        }
        if self.session_resumption_timeout_ms == 0 {
            return Err("session_resumption_timeout_ms must be greater than 0");
        }
        if self.jitter_factor < 0.0 || self.jitter_factor > 0.5 {
            return Err("jitter_factor must be in [0.0, 0.5]");
        }
        Ok(())
    }

    /// Create a `ReconnectPolicy` compatible with this config.
    #[must_use]
    pub fn to_policy(&self) -> ReconnectPolicy {
        ReconnectPolicy::ExponentialBackoff {
            initial: Duration::from_millis(self.base_backoff_ms),
            max: Duration::from_millis(self.max_backoff_ms),
            multiplier_millis: 2000,
        }
    }
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// ReconnectPhase -- high-level reconnect state machine
// ---------------------------------------------------------------------------

/// High-level state machine governing session reconnection.
///
/// Tracks where we are in the reconnect lifecycle:
/// idle, backing off, attempting session resumption, resumed, or exhausted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconnectPhase {
    /// No reconnect in progress.
    Idle,
    /// Waiting before the next reconnect attempt.
    BackingOff {
        /// Current attempt number (1-based).
        attempt: u32,
        /// When the backoff period ends and we may retry.
        deadline: Instant,
    },
    /// Session resumption handshake in progress.
    Resuming {
        /// Target session identifier.
        session_id: SessionId,
    },
    /// Session successfully resumed.
    Resumed,
    /// All retries exhausted, session must close.
    Exhausted,
}

impl ReconnectPhase {
    /// Whether reconnect attempts have been exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        matches!(self, Self::Exhausted)
    }

    /// Whether the phase allows attempting a reconnect.
    #[must_use]
    pub fn can_attempt(&self) -> bool {
        matches!(self, Self::Idle | Self::BackingOff { .. })
    }

    /// Human-readable label for logging.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::BackingOff { .. } => "backing_off",
            Self::Resuming { .. } => "resuming",
            Self::Resumed => "resumed",
            Self::Exhausted => "exhausted",
        }
    }
}

impl fmt::Display for ReconnectPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SessionResumeRequest -- domain-separated resume-token wire type
// ---------------------------------------------------------------------------

/// Domain context for session resume token derivation.
const SESSION_RESUME_DOMAIN: &str = "tidefs-transport-session-resume-v1";
/// Domain context for session resume response digest.
const SESSION_RESUME_RESPONSE_DOMAIN: &str = "tidefs-transport-session-resume-resp-v1";

/// Request sent from the reconnecting node to the peer to resume a
/// previously established session.
///
/// The `resume_token` is a BLAKE3-256 keyed hash of the session key
/// material proving possession of the original session secret.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionResumeRequest {
    /// The session being resumed.
    pub session_id: u64,
    /// BLAKE3-256 keyed hash: keyed_hash(session_key, DOMAIN || session_id_be).
    pub resume_token: [u8; 32],
    /// Last sequence number acknowledged before the disconnection.
    pub last_acknowledged_seq: MessageSequenceNumber,
    /// The reconnecting peer's last-known membership epoch.
    pub epoch: u64,
}

impl SessionResumeRequest {
    /// Construct a new resume request, computing the resume token
    /// from the session key material.
    #[must_use]
    pub fn new(
        session_id: u64,
        session_key: &[u8; 32],
        last_acknowledged_seq: MessageSequenceNumber,
        epoch: u64,
    ) -> Self {
        let resume_token = compute_resume_token(session_key, session_id);
        Self {
            session_id,
            resume_token,
            last_acknowledged_seq,
            epoch,
        }
    }

    /// Verify that the resume token in this request matches what we
    /// expect for the given session key and session id.
    #[must_use]
    pub fn verify_token(&self, session_key: &[u8; 32]) -> bool {
        let expected = compute_resume_token(session_key, self.session_id);
        constant_time_eq(&expected, &self.resume_token)
    }
}

/// Compute a BLAKE3-256 keyed resume token.
///
/// `token = keyed_hash(session_key, DOMAIN || u64::to_be_bytes(session_id))`
#[must_use]
fn compute_resume_token(session_key: &[u8; 32], session_id: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(session_key);
    hasher.update(SESSION_RESUME_DOMAIN.as_bytes());
    hasher.update(&session_id.to_be_bytes());
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// SessionResumeResponse -- domain-separated response wire type
// ---------------------------------------------------------------------------

/// Response to a session resumption request.
///
/// Carries a BLAKE3-256 domain-separated digest over the response
/// fields for tamper detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionResumeResponse {
    /// Whether the peer accepted the resumption.
    pub accepted: bool,
    /// New base sequence number (first message after resumption).
    pub new_seq_base: MessageSequenceNumber,
    /// Flow-control credit window re-advertised by the peer.
    pub flow_credit_window: u32,
    /// BLAKE3-256 domain-separated digest of the response fields.
    pub digest: [u8; 32],
}

impl SessionResumeResponse {
    /// Construct a signed resume response.
    #[must_use]
    pub fn new(
        accepted: bool,
        new_seq_base: MessageSequenceNumber,
        flow_credit_window: u32,
        session_key: &[u8; 32],
    ) -> Self {
        let mut resp = Self {
            accepted,
            new_seq_base,
            flow_credit_window,
            digest: [0u8; 32],
        };
        resp.digest = resp.compute_digest(session_key);
        resp
    }

    /// Verify the BLAKE3 keyed digest of this response.
    #[must_use]
    pub fn verify(&self, session_key: &[u8; 32]) -> bool {
        let expected = self.compute_digest(session_key);
        constant_time_eq(&expected, &self.digest)
    }

    /// Build the rejection response with no-op fields.
    #[must_use]
    pub fn rejected(session_key: &[u8; 32]) -> Self {
        Self::new(false, MessageSequenceNumber::ZERO, 0, session_key)
    }

    /// Build the acceptance response.
    #[must_use]
    pub fn accepted(
        new_seq_base: MessageSequenceNumber,
        flow_credit_window: u32,
        session_key: &[u8; 32],
    ) -> Self {
        Self::new(true, new_seq_base, flow_credit_window, session_key)
    }

    /// Compute the keyed BLAKE3-256 digest over the response payload.
    fn compute_digest(&self, session_key: &[u8; 32]) -> [u8; 32] {
        let mut payload = Vec::with_capacity(32);
        payload.push(self.accepted as u8);
        payload.extend_from_slice(&self.new_seq_base.0.to_be_bytes());
        payload.extend_from_slice(&self.flow_credit_window.to_be_bytes());

        let mut hasher = blake3::Hasher::new_keyed(session_key);
        hasher.update(SESSION_RESUME_RESPONSE_DOMAIN.as_bytes());
        hasher.update(&payload);
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// ReconnectError
// ---------------------------------------------------------------------------

/// Errors that can occur during session reconnection.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ReconnectError {
    /// All retry attempts were exhausted without successful reconnection.
    #[error("max retries ({max_retries}) exhausted for session {session_id}")]
    MaxRetriesExhausted { session_id: u64, max_retries: u32 },
    /// The peer rejected the session resumption request.
    #[error("session {session_id} resume rejected: {reason}")]
    ResumeRejected { session_id: u64, reason: String },
    /// The session resumption handshake timed out.
    #[error("session {session_id} resume timed out after {timeout_ms}ms")]
    ResumeTimeout { session_id: u64, timeout_ms: u64 },
    /// The session has expired and cannot be resumed.
    #[error("session {session_id} expired, cannot resume")]
    SessionExpired { session_id: u64 },
    /// The reconnecting peer's claimed epoch is behind the current
    /// membership epoch. The peer must catch up before it can resume.
    #[error("session {session_id} stale epoch: claimed {claimed_epoch} < current {current_epoch}")]
    StaleEpoch {
        session_id: u64,
        claimed_epoch: u64,
        current_epoch: u64,
    },
    /// The reconnecting peer has departed the cluster (drained or
    /// failed) and is no longer a member.
    #[error("session {session_id} peer {peer_id} has departed the cluster")]
    PeerDeparted { session_id: u64, peer_id: u64 },
    /// The reconnecting peer is not in the current membership roster.
    #[error("session {session_id} peer {peer_id} is not in the current roster")]
    NotInRoster { session_id: u64, peer_id: u64 },
    /// The peer rejected the resume request because the reconnecting
    /// peer's epoch is stale. This is a terminal error: the reconnecting
    /// peer must obtain the current epoch before retrying.
    #[error("session {session_id} resume rejected: peer reports stale epoch (claimed {claimed_epoch}, current {current_epoch})")]
    ResumeStaleEpoch { session_id: u64, claimed_epoch: u64, current_epoch: u64 },
}

// ---------------------------------------------------------------------------
// Constant-time comparison helper
// ---------------------------------------------------------------------------

fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut acc: u8 = 0;
    for i in 0..32 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// ReconnectDriver -- runtime reconnect orchestrator
// ---------------------------------------------------------------------------

/// Runtime driver that executes the session resumption reconnect protocol.
///
/// Combines `ReconnectConfig`, `ReconnectPhase`, and `ReconnectState` into a
/// single state machine that drives the reconnect loop. It holds the session
/// key material needed to construct and verify `SessionResumeRequest` and
/// `SessionResumeResponse` wire types.
///
/// ## Lifecycle
///
/// 1. Created via `ReconnectDriver::new()` with `Idle` phase.
/// 2. On disconnect, `start_reconnect()` transitions to `BackingOff` and
///    computes the first backoff duration.
/// 3. After the backoff expires, `enter_resuming()` transitions to `Resuming`.
/// 4. When a `SessionResumeResponse` arrives, `handle_resume_response()`
///    processes it: acceptance → `Resumed`, rejection → next backoff cycle
///    or `Exhausted`.
/// 5. `reset()` returns the driver to `Idle` for the next disconnect cycle.
pub struct ReconnectDriver {
    /// Configuration governing retry budget, timeouts, and backoff.
    pub config: ReconnectConfig,
    /// Current phase in the reconnect lifecycle.
    pub phase: ReconnectPhase,
    /// Underlying backoff state machine.
    pub state: ReconnectState,
    /// Target session identifier.
    pub session_id: u64,
    /// 32-byte session key used for resume token construction and
    /// response verification.
    pub session_key: [u8; 32],
    /// The reconnecting peer's current membership epoch.
    pub epoch: u64,
}

impl ReconnectDriver {
    /// Create a new reconnect driver in `Idle` phase.
    ///
    /// Uses epoch 0 by default; prefer [`with_epoch`](Self::with_epoch)
    /// when the current membership epoch is known.
    #[must_use]
    pub fn new(session_id: u64, session_key: [u8; 32], config: ReconnectConfig) -> Self {
        Self::with_epoch(session_id, session_key, config, 0)
    }

    /// Create a new reconnect driver with an explicit membership epoch.
    #[must_use]
    pub fn with_epoch(session_id: u64, session_key: [u8; 32], config: ReconnectConfig, epoch: u64) -> Self {
        let max_retries = config.max_retries;
        let policy = config.to_policy();
        let mut s = ReconnectState::with_policy(policy);
        s.max_attempts = max_retries;
        Self {
            config,
            phase: ReconnectPhase::Idle,
            state: s,
            session_id,
            session_key,
            epoch,
        }
    }

    /// Start the reconnect sequence from `Idle`.
    ///
    /// Transitions to `BackingOff` and returns the duration to wait
    /// before the first attempt.
    #[must_use]
    pub fn start_reconnect(&mut self) -> Duration {
        self.compute_backoff()
    }

    /// Compute the next backoff duration (with jitter) and advance
    /// the state machine to `BackingOff`.
    fn compute_backoff(&mut self) -> Duration {
        let base = self.state.next_backoff();
        let jittered = apply_jitter(base, self.config.jitter_factor);
        self.phase = ReconnectPhase::BackingOff {
            attempt: self.state.attempt,
            deadline: Instant::now() + jittered,
        };
        jittered
    }

    /// Transition from `BackingOff` to `Resuming`.
    ///
    /// Call this when the backoff deadline has elapsed and the caller
    /// is ready to attempt session resumption.
    pub fn enter_resuming(&mut self) {
        self.phase = ReconnectPhase::Resuming {
            session_id: SessionId::new(self.session_id),
        };
    }

    /// Handle a session resume response.
    ///
    /// On acceptance, transitions to `Resumed` and resets the backoff
    /// counter. On rejection, loops back to `BackingOff` if retries
    /// remain, or transitions to `Exhausted` if exhausted.
    ///
    /// ## Errors
    ///
    /// Returns `ReconnectError` on rejection, timeout, or exhaustion.
    pub fn handle_resume_response(
        &mut self,
        response: &SessionResumeResponse,
    ) -> Result<(), ReconnectError> {
        // Verify the response digest
        if !response.verify(&self.session_key) {
            return Err(ReconnectError::ResumeRejected {
                session_id: self.session_id,
                reason: "response digest verification failed".into(),
            });
        }

        if response.accepted {
            self.phase = ReconnectPhase::Resumed;
            self.state.reset();
            Ok(())
        } else {
            self.advance_or_exhaust()
        }
    }

    /// Handle a resume timeout: either retry or exhaust.
    ///
    /// ## Errors
    ///
    /// Returns `ReconnectError::ResumeTimeout` if retries remain,
    /// or `ReconnectError::MaxRetriesExhausted` if exhausted.
    pub fn handle_timeout(&mut self) -> Result<(), ReconnectError> {
        if self.phase.is_exhausted() {
            return Err(ReconnectError::MaxRetriesExhausted {
                session_id: self.session_id,
                max_retries: self.config.max_retries,
            });
        }
        Err(ReconnectError::ResumeTimeout {
            session_id: self.session_id,
            timeout_ms: self.config.session_resumption_timeout_ms,
        })
    }

    /// Advance to the next retry or exhaust.
    fn advance_or_exhaust(&mut self) -> Result<(), ReconnectError> {
        if self.state.is_exhausted() {
            self.phase = ReconnectPhase::Exhausted;
            return Err(ReconnectError::MaxRetriesExhausted {
                session_id: self.session_id,
                max_retries: self.config.max_retries,
            });
        }
        // Compute next backoff and stay in BackingOff
        self.compute_backoff();
        Err(ReconnectError::ResumeRejected {
            session_id: self.session_id,
            reason: "peer rejected resume request".into(),
        })
    }

    /// Explicitly mark the reconnect as exhausted (e.g., session expired).
    pub fn mark_exhausted(&mut self) {
        self.phase = ReconnectPhase::Exhausted;
    }

    /// Build a `SessionResumeRequest` from the current driver state.
    #[must_use]
    pub fn build_resume_request(
        &self,
        last_acknowledged_seq: MessageSequenceNumber,
    ) -> SessionResumeRequest {
        SessionResumeRequest::new(self.session_id, &self.session_key, last_acknowledged_seq, self.epoch)
    }

    /// Verify a `SessionResumeResponse` digest against the stored key.
    #[must_use]
    pub fn verify_response(&self, response: &SessionResumeResponse) -> bool {
        response.verify(&self.session_key)
    }

    /// Reset the driver to `Idle` (e.g., after successful reconnection
    /// so it's ready for the next disconnect cycle).
    pub fn reset(&mut self) {
        self.state.reset();
        self.phase = ReconnectPhase::Idle;
    }

    /// Whether reconnect attempts are exhausted.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.phase.is_exhausted()
    }

    /// Current attempt number (1-based).
    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.state.attempt
    }
}

/// Apply uniform jitter to a duration. The result is in
/// `[base * (1 - fraction), base * (1 + fraction)]`.
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
// Reconnect loop -- top-level async reconnect executor
// ---------------------------------------------------------------------------

/// Core reconnect loop: attempts session resumption with exponential
/// backoff + jitter until success or `max_retries` exhausted.
///
/// This function models the async reconnect loop that would be spawned
/// as a tokio task by the session's disconnect handler. It integrates
/// `ReconnectDriver` with the transport backend's connection capability.
///
/// ## Parameters
///
/// - `driver`: the reconnect state machine.
/// - `last_acknowledged_seq`: last message seq ack'd before disconnect.
/// - `attempt_connect`: async closure that attempts a fresh TCP/TLS
///   connection to the peer and returns a channel for sending the
///   resume request and receiving the response.
pub async fn reconnect_loop<F, Fut>(
    driver: &mut ReconnectDriver,
    last_acknowledged_seq: MessageSequenceNumber,
    mut attempt_connect: F,
) -> Result<(), ReconnectError>
where
    F: FnMut(SessionResumeRequest) -> Fut,
    Fut: std::future::Future<Output = Result<SessionResumeResponse, ReconnectError>>,
{
    let backoff = driver.start_reconnect();

    loop {
        if driver.is_exhausted() {
            return Err(ReconnectError::MaxRetriesExhausted {
                session_id: driver.session_id,
                max_retries: driver.config.max_retries,
            });
        }

        // Wait for the backoff period
        if backoff > Duration::ZERO {
            tokio::time::sleep(backoff).await;
        }

        // Transition to Resuming and build the resume request
        driver.enter_resuming();
        let request = driver.build_resume_request(last_acknowledged_seq);

        // Attempt session resumption with timeout
        let timeout = Duration::from_millis(driver.config.session_resumption_timeout_ms);
        let result = tokio::time::timeout(timeout, attempt_connect(request)).await;

        match result {
            Ok(Ok(response)) => {
                match driver.handle_resume_response(&response) {
                    Ok(()) => {
                        // Success: session resumed
                        return Ok(());
                    }
                    Err(ReconnectError::ResumeRejected { .. }) => {
                        // Peer rejected; backoff and retry
                        continue;
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            Ok(Err(e)) => {
                // Connection-level error; backoff and retry
                if driver.state.is_exhausted() {
                    driver.mark_exhausted();
                    return Err(e);
                }
                driver.compute_backoff();
            }
            Err(_elapsed) => {
                // Timeout; backoff and retry
                if driver.state.is_exhausted() {
                    driver.mark_exhausted();
                    return Err(ReconnectError::ResumeTimeout {
                        session_id: driver.session_id,
                        timeout_ms: driver.config.session_resumption_timeout_ms,
                    });
                }
                driver.compute_backoff();
            }
        }
    }
}
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    // -- ReconnectConfig tests --

    #[test]
    fn config_default_is_valid() {
        let cfg = ReconnectConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_zero_max_retries_invalid() {
        let cfg = ReconnectConfig {
            max_retries: 0,
            ..ReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_base_backoff_invalid() {
        let cfg = ReconnectConfig {
            base_backoff_ms: 0,
            ..ReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_max_less_than_base_invalid() {
        let cfg = ReconnectConfig {
            base_backoff_ms: 5000,
            max_backoff_ms: 1000,
            ..ReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_zero_timeout_invalid() {
        let cfg = ReconnectConfig {
            session_resumption_timeout_ms: 0,
            ..ReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_jitter_out_of_bounds_invalid() {
        let cfg = ReconnectConfig {
            jitter_factor: 1.0,
            ..ReconnectConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_to_policy_maps_fields() {
        let cfg = ReconnectConfig {
            base_backoff_ms: 200,
            max_backoff_ms: 10_000,
            ..ReconnectConfig::default()
        };
        let policy = cfg.to_policy();
        match policy {
            ReconnectPolicy::ExponentialBackoff { initial, max, .. } => {
                assert_eq!(initial, Duration::from_millis(200));
                assert_eq!(max, Duration::from_millis(10_000));
            }
            _ => panic!("expected ExponentialBackoff"),
        }
    }

    // -- ReconnectPhase tests --

    #[test]
    fn phase_idle_can_attempt() {
        let phase = ReconnectPhase::Idle;
        assert!(phase.can_attempt());
        assert!(!phase.is_exhausted());
    }

    #[test]
    fn phase_backing_off_can_attempt() {
        let phase = ReconnectPhase::BackingOff {
            attempt: 1,
            deadline: Instant::now(),
        };
        assert!(phase.can_attempt());
        assert!(!phase.is_exhausted());
    }

    #[test]
    fn phase_resumed_not_exhausted() {
        let phase = ReconnectPhase::Resumed;
        assert!(!phase.is_exhausted());
        assert!(!phase.can_attempt());
    }

    #[test]
    fn phase_exhausted_is_terminal() {
        let phase = ReconnectPhase::Exhausted;
        assert!(phase.is_exhausted());
        assert!(!phase.can_attempt());
    }

    #[test]
    fn phase_resuming_cannot_attempt() {
        let phase = ReconnectPhase::Resuming {
            session_id: SessionId(42),
        };
        assert!(!phase.can_attempt());
        assert!(!phase.is_exhausted());
    }

    #[test]
    fn phase_display_and_as_str() {
        assert_eq!(ReconnectPhase::Idle.as_str(), "idle");
        assert_eq!(ReconnectPhase::Resumed.as_str(), "resumed");
        assert_eq!(ReconnectPhase::Exhausted.as_str(), "exhausted");
        assert_eq!(
            format!(
                "{}",
                ReconnectPhase::Resuming {
                    session_id: SessionId(1)
                }
            ),
            "resuming"
        );
    }

    // -- SessionResumeRequest tests --

    #[test]
    fn resume_request_token_roundtrip() {
        let session_key = [0xabu8; 32];
        let session_id = 42u64;
        let seq = MessageSequenceNumber(100);

        let req = SessionResumeRequest::new(session_id, &session_key, seq, 0);
        assert_eq!(req.session_id, 42);
        assert_eq!(req.last_acknowledged_seq, MessageSequenceNumber(100));

        // Token should verify with the correct key
        assert!(req.verify_token(&session_key));
    }

    #[test]
    fn resume_request_token_rejects_wrong_key() {
        let session_key = [0xabu8; 32];
        let wrong_key = [0xcd; 32];
        let req = SessionResumeRequest::new(42, &session_key, MessageSequenceNumber(100), 0);
        assert!(!req.verify_token(&wrong_key));
    }

    #[test]
    fn resume_request_token_rejects_wrong_session_id() {
        let session_key = [0xabu8; 32];
        let req = SessionResumeRequest::new(42, &session_key, MessageSequenceNumber(100), 0);
        // Manually alter the session_id without recomputing the token
        let mut tampered = req.clone();
        tampered.session_id = 99;
        assert!(!tampered.verify_token(&session_key));
    }

    #[test]
    fn resume_request_token_different_per_session() {
        let key = [0x12; 32];
        let req_a = SessionResumeRequest::new(1, &key, MessageSequenceNumber(0), 0);
        let req_b = SessionResumeRequest::new(2, &key, MessageSequenceNumber(0), 0);
        // Different session ids should produce different tokens
        assert_ne!(req_a.resume_token, req_b.resume_token);
    }

    #[test]
    fn resume_request_token_different_per_key() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let req_a = SessionResumeRequest::new(1, &key_a, MessageSequenceNumber(0), 0);
        let req_b = SessionResumeRequest::new(1, &key_b, MessageSequenceNumber(0), 0);
        assert_ne!(req_a.resume_token, req_b.resume_token);
    }

    // -- SessionResumeResponse tests --

    #[test]
    fn resume_response_accepted_verifies() {
        let session_key = [0x42u8; 32];
        let resp = SessionResumeResponse::accepted(MessageSequenceNumber(100), 64, &session_key);
        assert!(resp.accepted);
        assert_eq!(resp.new_seq_base, MessageSequenceNumber(100));
        assert_eq!(resp.flow_credit_window, 64);
        assert!(resp.verify(&session_key));
    }

    #[test]
    fn resume_response_rejected_verifies() {
        let session_key = [0x42u8; 32];
        let resp = SessionResumeResponse::rejected(&session_key);
        assert!(!resp.accepted);
        assert_eq!(resp.new_seq_base, MessageSequenceNumber::ZERO);
        assert_eq!(resp.flow_credit_window, 0);
        assert!(resp.verify(&session_key));
    }

    #[test]
    fn resume_response_fails_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x99u8; 32];
        let resp = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &key);
        assert!(!resp.verify(&wrong_key));
    }

    #[test]
    fn resume_response_tamper_detection() {
        let key = [0x42u8; 32];
        let mut resp = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &key);
        // Tamper with the accepted flag
        resp.accepted = false;
        assert!(!resp.verify(&key));
    }

    #[test]
    fn resume_response_tamper_seq_base() {
        let key = [0x42u8; 32];
        let mut resp = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &key);
        resp.new_seq_base = MessageSequenceNumber(999);
        assert!(!resp.verify(&key));
    }

    #[test]
    fn resume_response_tamper_flow_window() {
        let key = [0x42u8; 32];
        let mut resp = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &key);
        resp.flow_credit_window = 0;
        assert!(!resp.verify(&key));
    }

    #[test]
    fn resume_response_tamper_digest() {
        let key = [0x42u8; 32];
        let mut resp = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &key);
        resp.digest = [0u8; 32];
        assert!(!resp.verify(&key));
    }

    // -- ReconnectError tests --

    #[test]
    fn reconnect_error_display() {
        let err = ReconnectError::MaxRetriesExhausted {
            session_id: 7,
            max_retries: 5,
        };
        let msg = format!("{err}");
        assert!(msg.contains("7"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn reconnect_error_resume_rejected() {
        let err = ReconnectError::ResumeRejected {
            session_id: 3,
            reason: "stale token".into(),
        };
        assert_eq!(format!("{err}"), "session 3 resume rejected: stale token");
    }

    #[test]
    fn reconnect_error_timeout() {
        let err = ReconnectError::ResumeTimeout {
            session_id: 9,
            timeout_ms: 5000,
        };
        assert!(format!("{err}").contains("5000ms"));
    }

    #[test]
    fn reconnect_error_expired() {
        let err = ReconnectError::SessionExpired { session_id: 1 };
        assert!(format!("{err}").contains("1"));
    }

    // -- ReconnectDriver tests --

    fn make_driver() -> ReconnectDriver {
        let config = ReconnectConfig::default();
        let session_key = [0xabu8; 32];
        ReconnectDriver::new(42, session_key, config)
    }

    #[test]
    fn driver_new_starts_idle() {
        let driver = make_driver();
        assert!(matches!(driver.phase, ReconnectPhase::Idle));
        assert_eq!(driver.session_id, 42);
        assert!(!driver.is_exhausted());
    }

    #[test]
    fn driver_start_reconnect_transitions_to_backing_off() {
        let mut driver = make_driver();
        let backoff = driver.start_reconnect();
        assert!(backoff > Duration::ZERO);
        assert!(matches!(driver.phase, ReconnectPhase::BackingOff { .. }));
        assert!(driver.attempt() >= 1);
    }

    #[test]
    fn driver_enter_resuming_transitions_correctly() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();
        assert!(matches!(driver.phase, ReconnectPhase::Resuming { .. }));
    }

    #[test]
    fn driver_handle_resume_response_accepted() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();

        let response =
            SessionResumeResponse::accepted(MessageSequenceNumber(500), 64, &driver.session_key);
        let result = driver.handle_resume_response(&response);
        assert!(result.is_ok());
        assert!(matches!(driver.phase, ReconnectPhase::Resumed));
        assert_eq!(driver.attempt(), 0); // reset
    }

    #[test]
    fn driver_handle_resume_response_rejected_backoff_and_retry() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();

        let response = SessionResumeResponse::rejected(&driver.session_key);
        let result = driver.handle_resume_response(&response);
        assert!(result.is_err());
        match result {
            Err(ReconnectError::ResumeRejected { .. }) => {}
            _ => panic!("expected ResumeRejected"),
        }
        // Should go back to BackingOff for retry
        assert!(matches!(driver.phase, ReconnectPhase::BackingOff { .. }));
    }

    #[test]
    fn driver_handle_resume_response_tampered_digest() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();

        // Use wrong key to produce a tampered response
        let wrong_key = [0xFFu8; 32];
        let response = SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &wrong_key);
        let result = driver.handle_resume_response(&response);
        assert!(result.is_err());
        match result {
            Err(ReconnectError::ResumeRejected { .. }) => {}
            _ => panic!("expected ResumeRejected for tampered digest"),
        }
    }

    #[test]
    fn driver_exhausted_after_max_retries() {
        let config = ReconnectConfig {
            max_retries: 2,
            ..ReconnectConfig::default()
        };
        let mut driver = ReconnectDriver::new(1, [0x11u8; 32], config);

        // First attempt - reject
        let _ = driver.start_reconnect();
        driver.enter_resuming();
        let resp = SessionResumeResponse::rejected(&driver.session_key);
        let _ = driver.handle_resume_response(&resp);

        // After rejection, should be in BackingOff with attempt=1
        // Skip backoff and retry
        driver.enter_resuming();
        let _ = driver.handle_resume_response(&resp);

        // After second rejection, should be exhausted
        assert!(driver.is_exhausted());
    }

    #[test]
    fn driver_build_resume_request_produces_valid_token() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();

        let req = driver.build_resume_request(MessageSequenceNumber(42));
        assert_eq!(req.session_id, 42);
        assert_eq!(req.last_acknowledged_seq, MessageSequenceNumber(42));
        assert!(req.verify_token(&driver.session_key));
    }

    #[test]
    fn driver_verify_response_accepts_valid() {
        let driver = make_driver();
        let resp =
            SessionResumeResponse::accepted(MessageSequenceNumber(10), 32, &driver.session_key);
        assert!(driver.verify_response(&resp));
    }

    #[test]
    fn driver_verify_response_rejects_tampered() {
        let driver = make_driver();
        let mut resp =
            SessionResumeResponse::accepted(MessageSequenceNumber(10), 32, &driver.session_key);
        resp.accepted = false;
        assert!(!driver.verify_response(&resp));
    }

    #[test]
    fn driver_reset_returns_to_idle() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();
        let resp =
            SessionResumeResponse::accepted(MessageSequenceNumber(1), 32, &driver.session_key);
        let _ = driver.handle_resume_response(&resp);

        driver.reset();
        assert!(matches!(driver.phase, ReconnectPhase::Idle));
        assert_eq!(driver.attempt(), 0);
        assert!(!driver.is_exhausted());
    }

    #[test]
    fn driver_mark_exhausted() {
        let mut driver = make_driver();
        driver.mark_exhausted();
        assert!(driver.is_exhausted());
        assert!(matches!(driver.phase, ReconnectPhase::Exhausted));
    }

    #[test]
    fn driver_handle_timeout_returns_error() {
        let mut driver = make_driver();
        let _ = driver.start_reconnect();
        driver.enter_resuming();

        let result = driver.handle_timeout();
        assert!(result.is_err());
        match result {
            Err(ReconnectError::ResumeTimeout { .. }) => {}
            _ => panic!("expected ResumeTimeout"),
        }
    }

    // -- jitter tests --

    #[test]
    fn jitter_stays_within_bounds() {
        let base = Duration::from_millis(100);
        for _ in 0..50 {
            let j = apply_jitter(base, 0.2);
            let lower = Duration::from_millis(80); // base * (1 - 0.2)
            let upper = Duration::from_millis(120); // base * (1 + 0.2)
            assert!(j >= lower, "jitter too low: {j:?}");
            assert!(j <= upper, "jitter too high: {j:?}");
        }
    }

    #[test]
    fn jitter_zero_fraction_returns_base() {
        let base = Duration::from_millis(100);
        let result = apply_jitter(base, 0.0);
        assert_eq!(result, base);
    }
}
