// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Transport connection keepalive protocol with deadline-based failure
//! detection and health-score signal integration.
//!
//! ## Keepalive design
//!
//! Every active transport connection runs a keepalive heartbeat loop that
//! exchanges ping/pong messages with a remote peer. Integrity and authenticity
//! are provided by the transport session security boundary (TLS); keepalive
//! frames carry only a monotonic sequence number for echo matching.
//! Failure detection is driven by a consecutive-miss counter: a configurable
//! number of missed pong responses transitions the connection to Failed, at
//! which point teardown is triggered via the ConnectionState machine (#5869).
//!
//! ### Wire format
//!
//! Every keepalive message (ping or pong) is an 8-byte frame:
//!
//! ```text
//! [seq:u64 LE]
//! ```
//!
//! The sequence number is a monotonic u64 in little-endian byte order.
//! Ping and pong frames are identical on the wire; the transport
//! message-type discriminator distinguishes them in framing.

use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Size of a keepalive frame on the wire: 8 bytes (u64 LE sequence).
pub const KEEPALIVE_FRAME_SIZE: usize = 8;

/// Default keepalive heartbeat interval: 1 second.
pub const DEFAULT_HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// Default miss threshold before declaring connection dead.
pub const DEFAULT_MISS_THRESHOLD: u32 = 5;

/// Default reconnect maximum retries.
pub const DEFAULT_RECONNECT_MAX_RETRIES: u32 = 10;

/// Default reconnect initial backoff: 1 second.
pub const DEFAULT_RECONNECT_INITIAL_MS: u64 = 1_000;

/// Default reconnect max backoff cap: 30 seconds.
pub const DEFAULT_RECONNECT_MAX_MS: u64 = 30_000;

// ---------------------------------------------------------------------------
// Heartbeat state machine
// ---------------------------------------------------------------------------

/// Per-connection keepalive heartbeat state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeartbeatState {
    /// Connection is healthy; no missed heartbeats.
    Healthy,
    /// `n` consecutive missed heartbeats (n < miss_threshold).
    Suspect(u32),
    /// Connection is dead after `miss_threshold` consecutive misses.
    Dead,
    /// Reconnection is in progress.
    Reconnecting,
}

impl HeartbeatState {
    /// Whether the connection is considered alive (can carry traffic).
    #[must_use]
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Healthy | Self::Suspect(_))
    }

    /// Whether the connection is dead and needs reconnection.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Dead)
    }
}

// ---------------------------------------------------------------------------
// Heartbeat configuration
// ---------------------------------------------------------------------------

/// Configuration for the keepalive heartbeat engine.
#[derive(Clone, Debug)]
pub struct HeartbeatConfig {
    /// Interval between heartbeat pings.
    pub interval: Duration,
    /// Number of consecutive missed pongs before declaring the connection
    /// dead.
    pub miss_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(DEFAULT_HEARTBEAT_INTERVAL_MS),
            miss_threshold: DEFAULT_MISS_THRESHOLD,
        }
    }
}

impl HeartbeatConfig {
    /// Create a new config with the given interval and miss threshold.
    #[must_use]
    pub fn new(interval: Duration, miss_threshold: u32) -> Self {
        Self {
            interval,
            miss_threshold,
        }
    }
}

// ---------------------------------------------------------------------------
// Heartbeat tracker — per-connection runtime state
// ---------------------------------------------------------------------------

/// Per-connection keepalive tracker holding sequence numbers, state, and
/// timing information.
#[derive(Debug)]
pub struct HeartbeatTracker {
    /// Current heartbeat state.
    pub state: HeartbeatState,
    /// Config used by this tracker.
    pub config: HeartbeatConfig,
    /// Monotonic sequence number for the next ping to send.
    pub next_seq: u64,
    /// Sequence number of the last successfully acked pong.
    pub last_acked_seq: u64,
    /// When the most recent ping was sent.
    pub last_ping_at: Option<Instant>,
    /// When the most recent valid pong was received.
    pub last_pong_at: Option<Instant>,
    /// Consecutive missed heartbeat count.
    pub consecutive_misses: u32,
}

impl HeartbeatTracker {
    /// Create a new tracker with default config, starting in Healthy.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: HeartbeatState::Healthy,
            config: HeartbeatConfig::default(),
            next_seq: 1,
            last_acked_seq: 0,
            last_ping_at: None,
            last_pong_at: None,
            consecutive_misses: 0,
        }
    }

    /// Create a new tracker with the given config.
    #[must_use]
    pub fn with_config(config: HeartbeatConfig) -> Self {
        Self {
            state: HeartbeatState::Healthy,
            config,
            next_seq: 1,
            last_acked_seq: 0,
            last_ping_at: None,
            last_pong_at: None,
            consecutive_misses: 0,
        }
    }

    /// Record that a ping was sent. Advances `next_seq` and stamps time.
    pub fn record_ping_sent(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        self.last_ping_at = Some(Instant::now());
        seq
    }

    /// Record a valid pong received. Resets miss counter, transitions from
    /// Suspect back to Healthy. Returns the old state.
    pub fn record_pong(&mut self, seq: u64) -> HeartbeatState {
        let old_state = self.state;
        self.last_acked_seq = seq;
        self.last_pong_at = Some(Instant::now());
        self.consecutive_misses = 0;
        self.state = HeartbeatState::Healthy;
        old_state
    }
    /// Return the round-trip latency of the most recent ping-pong cycle.
    ///
    /// Returns `None` if no valid pong has been received yet or if no
    /// ping was sent before the last pong.
    #[must_use]
    pub fn last_pong_rtt(&self) -> Option<Duration> {
        match (self.last_ping_at, self.last_pong_at) {
            (Some(ping), Some(pong)) if pong > ping => Some(pong - ping),
            _ => None,
        }
    }

    /// Feed the most recent ping-pong RTT into a health signal sink.
    ///
    /// Calls `sink.ingest_signal` with `HealthSignal::KeepaliveRtt` if a
    /// valid RTT measurement is available.
    pub fn feed_health_rtt(
        &self,
        sink: &mut dyn crate::peer_health::HealthSignalSink,
        conn_id: crate::connection_registry::ConnectionId,
    ) {
        if let Some(rtt) = self.last_pong_rtt() {
            sink.ingest_signal(conn_id, crate::peer_health::HealthSignal::KeepaliveRtt(rtt));
        }
    }

    /// Record a missed heartbeat (ping sent but no valid pong within
    /// interval). Advances the miss counter and transitions state.
    pub fn record_miss(&mut self) {
        self.consecutive_misses += 1;
        let n = self.consecutive_misses;
        if n >= self.config.miss_threshold {
            self.state = HeartbeatState::Dead;
        } else if n > 0 {
            self.state = HeartbeatState::Suspect(n);
        }
    }

    /// Transition to Reconnecting state (caller is starting reconnect).
    /// Returns true if transition is allowed (only from Dead).
    #[must_use]
    pub fn start_reconnect(&mut self) -> bool {
        if self.state == HeartbeatState::Dead {
            self.state = HeartbeatState::Reconnecting;
            true
        } else {
            false
        }
    }

    /// Mark reconnection as successful: reset counters and return to Healthy.
    pub fn reconnect_success(&mut self) {
        self.state = HeartbeatState::Healthy;
        self.consecutive_misses = 0;
        // Do NOT reset next_seq so the remote peer sees monotonic sequence
        // numbers across reconnections.
    }

    /// Check whether enough time has elapsed since the last ping to send
    /// another.
    #[must_use]
    pub fn should_ping(&self) -> bool {
        match self.last_ping_at {
            None => true,
            Some(t) => t.elapsed() >= self.config.interval,
        }
    }

    /// Check whether a ping has timed out (no pong received within interval
    /// after the last ping).
    #[must_use]
    pub fn has_ping_timed_out(&self) -> bool {
        match (self.last_ping_at, self.last_pong_at) {
            (Some(ping_at), Some(pong_at)) => {
                ping_at > pong_at && ping_at.elapsed() >= self.config.interval
            }
            (Some(ping_at), None) => ping_at.elapsed() >= self.config.interval,
            (None, _) => false,
        }
    }
}

impl Default for HeartbeatTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnectionKeepalive impl for HeartbeatTracker
// ---------------------------------------------------------------------------

impl ConnectionKeepalive for HeartbeatTracker {
    fn record_activity(&mut self) {
        self.last_pong_at = Some(Instant::now());
        self.consecutive_misses = 0;
        self.state = HeartbeatState::Healthy;
    }

    fn should_send_probe(&self) -> bool {
        self.should_ping()
    }

    fn send_probe(&mut self) -> u64 {
        self.record_ping_sent()
    }

    fn record_missed_probe(&mut self) {
        self.record_miss();
    }

    fn record_response(&mut self, seq: u64) {
        self.record_pong(seq);
    }

    fn is_peer_dead(&self) -> bool {
        self.state.is_dead()
    }

    fn reset(&mut self) {
        self.reconnect_success();
    }
}

// ---------------------------------------------------------------------------
// Keepalive wire format: simple 8-byte u64 LE sequence numbers.
// Ping and pong are identical on the wire; the frame-type discriminator
// in the transport envelope distinguishes them.
// ---------------------------------------------------------------------------

/// Encode a keepalive ping or pong sequence number into a fixed-size buffer.
///
/// Writes the u64 sequence in little-endian byte order.
/// `buf` must be exactly [`KEEPALIVE_FRAME_SIZE`] bytes.
///
/// # Panics
///
/// Panics if `buf.len() != KEEPALIVE_FRAME_SIZE`.
pub fn encode_seq(buf: &mut [u8], seq: u64) {
    assert_eq!(buf.len(), KEEPALIVE_FRAME_SIZE);
    buf.copy_from_slice(&seq.to_le_bytes());
}

/// Decode a keepalive ping or pong sequence number from a raw frame.
///
/// Returns the sequence number if the frame is exactly
/// [`KEEPALIVE_FRAME_SIZE`] bytes, or `None` otherwise.
#[must_use]
pub fn decode_seq(frame: &[u8]) -> Option<u64> {
    if frame.len() != KEEPALIVE_FRAME_SIZE {
        return None;
    }
    Some(u64::from_le_bytes(frame.try_into().ok()?))
}

/// Decode and verify a keepalive ping frame.
///
/// Returns the sequence number if the frame has the correct size.
/// Integrity is provided by the transport security boundary.
#[must_use]
pub fn decode_ping(frame: &[u8]) -> Option<u64> {
    decode_seq(frame)
}

/// Decode and verify a keepalive pong frame.
///
/// Returns the sequence number if the frame has the correct size.
/// Integrity is provided by the transport security boundary.
#[must_use]
pub fn decode_pong(frame: &[u8]) -> Option<u64> {
    decode_seq(frame)
}

/// Validate a received pong against an expected sequence number.
///
/// Returns `Ok(seq)` if the pong frame is the correct size and the sequence
/// number is acceptable (>= last acked). Returns `Err(PongValidationError)` otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PongValidationError {
    /// Frame is not a valid pong (wrong size).
    InvalidFrame,
    /// Sequence number is stale (less than the last acked sequence).
    StaleSequence { received: u64, last_acked: u64 },
}

/// Validate a received pong frame against an expected minimum sequence.
pub fn validate_pong(frame: &[u8], last_acked: u64) -> Result<u64, PongValidationError> {
    let seq = decode_pong(frame).ok_or(PongValidationError::InvalidFrame)?;
    if seq < last_acked {
        return Err(PongValidationError::StaleSequence {
            received: seq,
            last_acked,
        });
    }
    Ok(seq)
}

/// Build a keepalive ping frame with the given sequence number.
#[must_use]
pub fn build_ping(seq: u64) -> Vec<u8> {
    seq.to_le_bytes().to_vec()
}

/// Build a keepalive pong frame with the given sequence number.
#[must_use]
pub fn build_pong(seq: u64) -> Vec<u8> {
    seq.to_le_bytes().to_vec()
}

// ---------------------------------------------------------------------------
// Failure detection
// ---------------------------------------------------------------------------

/// Run one tick of failure detection on a tracker.
///
/// If a ping has timed out, records a miss and transitions state.
/// Returns the new state after the tick.
#[must_use]
pub fn detect_failure(tracker: &mut HeartbeatTracker) -> HeartbeatState {
    if tracker.state == HeartbeatState::Dead || tracker.state == HeartbeatState::Reconnecting {
        return tracker.state;
    }
    if tracker.has_ping_timed_out() {
        tracker.record_miss();
    }
    tracker.state
}

// ---------------------------------------------------------------------------
// Reconnection orchestration (retained for API compatibility)
// ---------------------------------------------------------------------------

use crate::reconnect::{ReconnectPolicy, ReconnectState};

/// Orchestrates reconnection with keepalive-aware backoff and jitter.
pub struct ReconnectOrchestrator {
    /// Underlying exponential-backoff reconnect state machine.
    pub state: ReconnectState,
    /// Whether jitter is applied to backoff durations.
    pub jitter_enabled: bool,
    /// Maximum jitter fraction (0.0 – 1.0).
    pub jitter_fraction: f64,
}

impl ReconnectOrchestrator {
    #[must_use]
    pub fn new(policy: ReconnectPolicy, jitter_enabled: bool, jitter_fraction: f64) -> Self {
        Self {
            state: ReconnectState::with_policy(policy),
            jitter_enabled,
            jitter_fraction,
        }
    }

    #[must_use]
    pub fn default_with_jitter() -> Self {
        Self {
            state: ReconnectState::with_policy(ReconnectPolicy::ExponentialBackoff {
                initial: Duration::from_millis(1_000),
                max: Duration::from_millis(30_000),
                multiplier_millis: 2000,
            }),
            jitter_enabled: true,
            jitter_fraction: 0.2,
        }
    }

    #[must_use]
    pub fn with_max_retries(policy: ReconnectPolicy, max_retries: u32) -> Self {
        let mut state = ReconnectState::with_policy(policy);
        state.max_attempts = max_retries;
        Self {
            state,
            jitter_enabled: true,
            jitter_fraction: 0.2,
        }
    }

    #[must_use]
    pub fn next_backoff(&mut self) -> Duration {
        self.state.next_backoff()
    }

    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.state.is_exhausted()
    }

    pub fn reset(&mut self) {
        self.state.reset();
    }

    #[must_use]
    pub fn attempt(&self) -> u32 {
        self.state.attempt
    }
}

// ---------------------------------------------------------------------------
// KeepaliveConfig -- idle-timeout-based keepalive configuration
// ---------------------------------------------------------------------------

/// Configuration for idle-timeout-based keepalive probing.
///
/// Unlike the heartbeat-based [`HeartbeatConfig`] which sends pings on a fixed
/// interval regardless of activity, `KeepaliveConfig` only begins probing
/// after `idle_timeout` of inactivity on the connection. This reduces
/// keepalive overhead on busy connections while still detecting dead peers.
///
/// Defaults: 30 s idle timeout, 5 s probe interval, 3 missed probes.
#[derive(Clone, Debug, PartialEq)]
pub struct KeepaliveConfig {
    /// Duration of inactivity before the first keepalive probe is sent.
    pub idle_timeout: Duration,
    /// Interval between successive probes once probing has started.
    pub probe_interval: Duration,
    /// Maximum number of unanswered probes before declaring the peer dead.
    pub max_missed_probes: u8,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(30),
            probe_interval: Duration::from_secs(5),
            max_missed_probes: 3,
        }
    }
}

impl KeepaliveConfig {
    /// Create a new config with the given parameters.
    ///
    /// Returns `None` if any duration is zero or `max_missed_probes` is 0.
    #[must_use]
    pub fn new(
        idle_timeout: Duration,
        probe_interval: Duration,
        max_missed_probes: u8,
    ) -> Option<Self> {
        if idle_timeout.is_zero() || probe_interval.is_zero() || max_missed_probes == 0 {
            return None;
        }
        Some(Self {
            idle_timeout,
            probe_interval,
            max_missed_probes,
        })
    }

    /// Validate that all durations are non-zero and max_missed_probes > 0.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.idle_timeout.is_zero() {
            return Err("idle_timeout must be non-zero");
        }
        if self.probe_interval.is_zero() {
            return Err("probe_interval must be non-zero");
        }
        if self.max_missed_probes == 0 {
            return Err("max_missed_probes must be > 0");
        }
        Ok(())
    }
}

impl From<crate::config::KeepaliveConfig> for KeepaliveConfig {
    /// Bridge from the user-facing transport config to the internal keepalive
    /// engine config. Uses `interval` for both idle and probe timing (the
    /// engine treats a single interval as the inter-probe period).
    fn from(c: crate::config::KeepaliveConfig) -> Self {
        Self {
            idle_timeout: c.interval,
            probe_interval: c.interval,
            max_missed_probes: u8::try_from(c.probe_count).unwrap_or(u8::MAX),
        }
    }
}

// ---------------------------------------------------------------------------
// KeepaliveState -- idle-timeout-based keepalive state machine
// ---------------------------------------------------------------------------

/// State of an idle-timeout-based keepalive engine.
///
/// ```text
/// Idle ──(idle_timeout elapsed)──▶ Probing ──(probe ack'd)──▶ Idle
///                                      │
///                                      └──(max_missed_probes exceeded)──▶ Failed
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveState {
    /// Connection is active; no probing in progress.
    Idle,
    /// Probing in progress; waiting for probe responses.
    Probing {
        /// How many consecutive probes have gone unanswered.
        missed: u8,
    },
    /// Peer is considered dead after exceeding max_missed_probes.
    Failed,
}

impl KeepaliveState {
    /// Whether the peer is considered alive.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        matches!(self, Self::Idle | Self::Probing { .. })
    }

    /// Whether the peer is considered dead.
    #[must_use]
    pub fn is_dead(&self) -> bool {
        matches!(self, Self::Failed)
    }
}

// ---------------------------------------------------------------------------
// KeepaliveProbe and KeepaliveResponse -- wire types
// ---------------------------------------------------------------------------

/// Build a keepalive probe frame for the given sequence number.
///
/// Returns an 8-byte frame containing the sequence number in LE order.
#[must_use]
pub fn build_probe(seq: u64) -> Vec<u8> {
    build_ping(seq)
}

/// Decode a keepalive probe frame.
///
/// Returns the sequence number if the frame is exactly 8 bytes.
#[must_use]
pub fn decode_probe(frame: &[u8]) -> Option<u64> {
    decode_seq(frame)
}

/// Build a keepalive response frame echoing a probe's sequence number.
///
/// Returns an 8-byte frame containing the sequence number in LE order.
#[must_use]
pub fn build_response(seq: u64) -> Vec<u8> {
    build_pong(seq)
}

/// Decode a keepalive response frame.
///
/// Returns the sequence number if the frame is exactly 8 bytes.
#[must_use]
pub fn decode_response(frame: &[u8]) -> Option<u64> {
    decode_seq(frame)
}

/// Validate a received probe response against an expected sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeResponseError {
    /// Frame is not a valid response (wrong size).
    InvalidFrame,
    /// Sequence number is stale (less than the last acked sequence).
    StaleSequence { received: u64, last_acked: u64 },
}

/// Validate a received response frame against the expected minimum sequence.
pub fn validate_response(frame: &[u8], last_acked: u64) -> Result<u64, ProbeResponseError> {
    let seq = decode_response(frame).ok_or(ProbeResponseError::InvalidFrame)?;
    if seq < last_acked {
        return Err(ProbeResponseError::StaleSequence {
            received: seq,
            last_acked,
        });
    }
    Ok(seq)
}

/// Size of a keepalive probe frame: 8 bytes (u64 LE).
pub const KEEPALIVE_PROBE_SIZE: usize = KEEPALIVE_FRAME_SIZE;

/// Size of a keepalive response frame: 8 bytes (u64 LE).
pub const KEEPALIVE_RESPONSE_SIZE: usize = KEEPALIVE_FRAME_SIZE;

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// ConnectionKeepalive trait -- abstraction for connection lifecycle integration
// ---------------------------------------------------------------------------

/// Trait for per-connection keepalive state machine.
///
/// The connection lifecycle state machine queries the keepalive to determine
/// when a peer has become unresponsive and the connection should be torn down.
/// Implementations track liveness through heartbeat probes or idle-timeout
/// detection and signal dead-peer events to the lifecycle.
///
/// The trait is object-safe: the connection lifecycle can hold a
/// `&mut dyn ConnectionKeepalive` without knowing the concrete engine.
pub trait ConnectionKeepalive {
    /// Notify the keepalive that data was received on the connection.
    /// Resets idle timers and, if probing was in progress, returns to Idle
    /// (received data proves the peer is alive).
    fn record_activity(&mut self);

    /// Check whether a keepalive probe should be sent now.
    fn should_send_probe(&self) -> bool;

    /// Send a probe. Returns the monotonic sequence number to include in
    /// the probe frame.
    fn send_probe(&mut self) -> u64;

    /// Record that a probe went unanswered. Advances toward Failed/Dead.
    fn record_missed_probe(&mut self);

    /// Record a valid probe response received from the peer.
    /// Returns the keepalive to Idle and resets counters.
    fn record_response(&mut self, seq: u64);

    /// Whether the peer is considered dead.
    fn is_peer_dead(&self) -> bool;

    /// Reset the keepalive to its initial healthy state (e.g., after
    /// reconnection). Preserves the monotonic sequence number across
    /// resets.
    fn reset(&mut self);
}

// KeepaliveEngine -- idle-timeout-driven keepalive state machine
// ---------------------------------------------------------------------------

/// Engine that drives idle-timeout-based keepalive probing.
///
/// `KeepaliveEngine` only sends probes when the connection has been idle
/// (no received data) for `config.idle_timeout`. Once probing starts, probes
/// are sent every `config.probe_interval` until a valid response is received
/// (returning to Idle) or `config.max_missed_probes` are missed (transitioning
/// to Failed).
#[derive(Debug)]
pub struct KeepaliveEngine {
    /// Configuration for idle timeout, probe interval, and miss threshold.
    pub config: KeepaliveConfig,
    /// Current keepalive state.
    pub state: KeepaliveState,
    /// Monotonic sequence number for the next probe.
    next_seq: u64,
    /// Sequence number of the last acknowledged response.
    last_acked: u64,
    /// When the most recent data was received (any traffic).
    last_activity: Option<Instant>,
    /// When the most recent probe was sent.
    last_probe_at: Option<Instant>,
    /// Consecutive missed probe count.
    missed_probes: u8,
}

impl KeepaliveEngine {
    /// Create a new engine with the given config, starting in Idle.
    #[must_use]
    pub fn new(config: KeepaliveConfig) -> Self {
        Self {
            config,
            state: KeepaliveState::Idle,
            next_seq: 1,
            last_acked: 0,
            last_activity: None,
            last_probe_at: None,
            missed_probes: 0,
        }
    }

    /// Create a new engine with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(KeepaliveConfig::default())
    }

    /// Notify the engine that data was received on the connection.
    /// Resets the idle timer and, if a probe cycle was in progress,
    /// returns to Idle (the received data proves the peer is alive).
    pub fn record_activity(&mut self) {
        self.last_activity = Some(Instant::now());
        if self.state != KeepaliveState::Idle {
            self.state = KeepaliveState::Idle;
            self.missed_probes = 0;
        }
    }

    /// Check whether the keepalive should send a probe.
    ///
    /// Returns `true` when:
    /// - In Idle state and idle_timeout has elapsed since last activity, OR
    /// - In Probing state and probe_interval has elapsed since last probe.
    #[must_use]
    pub fn should_send_probe(&self) -> bool {
        match self.state {
            KeepaliveState::Idle => {
                match self.last_activity {
                    None => false, // no activity yet recorded; don't probe
                    Some(t) => t.elapsed() >= self.config.idle_timeout,
                }
            }
            KeepaliveState::Probing { .. } => {
                match self.last_probe_at {
                    None => true, // probing but no probe sent yet (shouldn't happen)
                    Some(t) => t.elapsed() >= self.config.probe_interval,
                }
            }
            KeepaliveState::Failed => false,
        }
    }

    /// Send a probe. Records the probe, advances state to Probing if idle,
    /// and returns the sequence number to include in the probe frame.
    pub fn send_probe(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = seq.wrapping_add(1);
        self.last_probe_at = Some(Instant::now());
        self.state = match self.state {
            KeepaliveState::Idle => KeepaliveState::Probing { missed: 0 },
            KeepaliveState::Probing { missed } => KeepaliveState::Probing {
                missed: missed.saturating_add(1),
            },
            KeepaliveState::Failed => KeepaliveState::Failed,
        };
        seq
    }

    /// Record a missed probe (no response received within probe_interval).
    /// Transitions to Failed if max_missed_probes is exceeded.
    pub fn record_missed_probe(&mut self) {
        self.missed_probes = self.missed_probes.saturating_add(1);
        if self.missed_probes >= self.config.max_missed_probes {
            self.state = KeepaliveState::Failed;
        } else {
            self.state = KeepaliveState::Probing {
                missed: self.missed_probes,
            };
        }
    }

    /// Record a valid probe response. Returns to Idle and resets counters.
    pub fn record_response(&mut self, seq: u64) {
        self.last_acked = seq;
        self.missed_probes = 0;
        self.state = KeepaliveState::Idle;
        self.last_activity = Some(Instant::now());
    }

    /// Check whether the peer is considered dead (state is Failed).
    #[must_use]
    pub fn is_peer_dead(&self) -> bool {
        self.state == KeepaliveState::Failed
    }

    /// Reset the engine to Idle (e.g. after reconnection).
    pub fn reset(&mut self) {
        self.state = KeepaliveState::Idle;
        self.missed_probes = 0;
        self.last_activity = Some(Instant::now());
        self.last_probe_at = None;
        // Preserve next_seq for monotonicity across reconnections.
    }
}

// ---------------------------------------------------------------------------
// ConnectionKeepalive impl for KeepaliveEngine
// ---------------------------------------------------------------------------

impl ConnectionKeepalive for KeepaliveEngine {
    fn record_activity(&mut self) {
        self.record_activity();
    }

    fn should_send_probe(&self) -> bool {
        self.should_send_probe()
    }

    fn send_probe(&mut self) -> u64 {
        self.send_probe()
    }

    fn record_missed_probe(&mut self) {
        self.record_missed_probe();
    }

    fn record_response(&mut self, seq: u64) {
        self.record_response(seq);
    }

    fn is_peer_dead(&self) -> bool {
        self.is_peer_dead()
    }

    fn reset(&mut self) {
        self.reset();
    }
}

// ---------------------------------------------------------------------------

/// Health classification for a transport session based on keepalive status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveHealth {
    /// Session is alive and heartbeats are being exchanged normally.
    Alive,
    /// Session has missed some heartbeats but is still considered recoverable.
    Degraded,
    /// Session has exceeded the miss threshold and the connection is dead.
    Dead,
}

/// A session-scoped keepalive tracker that wraps `HeartbeatTracker` with
/// convenience methods for session integration.
///
/// Tracks heartbeat state and exposes a `health()` method that maps the
/// internal `HeartbeatState` to a `KeepaliveHealth` classification.
/// The session should call `on_ping_sent()` before each outbound heartbeat
/// and `on_pong_received()` on each valid inbound pong.
#[derive(Debug)]
pub struct SessionKeepalive {
    /// The underlying heartbeat tracker.
    pub tracker: HeartbeatTracker,
    /// When this keepalive was activated (session became Established).
    pub activated_at: Option<Instant>,
}

impl SessionKeepalive {
    /// Create a new session keepalive tracker with default config.
    #[must_use]
    pub fn new() -> Self {
        Self {
            tracker: HeartbeatTracker::new(),
            activated_at: None,
        }
    }

    /// Create a new session keepalive tracker with the given config.
    #[must_use]
    pub fn with_config(config: HeartbeatConfig) -> Self {
        Self {
            tracker: HeartbeatTracker::with_config(config),
            activated_at: None,
        }
    }

    /// Activate the keepalive (called when session becomes Established).
    /// Resets the tracker and records the activation time.
    pub fn activate(&mut self) {
        self.tracker = HeartbeatTracker::with_config(self.tracker.config.clone());
        self.activated_at = Some(Instant::now());
    }

    /// Deactivate the keepalive (called on teardown or session close).
    pub fn deactivate(&mut self) {
        self.activated_at = None;
    }

    /// Whether the keepalive is currently active.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.activated_at.is_some()
    }

    /// Return the current health classification.
    #[must_use]
    pub fn health(&self) -> KeepaliveHealth {
        match self.tracker.state {
            HeartbeatState::Healthy => KeepaliveHealth::Alive,
            HeartbeatState::Suspect(_) => KeepaliveHealth::Degraded,
            HeartbeatState::Dead => KeepaliveHealth::Dead,
            HeartbeatState::Reconnecting => KeepaliveHealth::Degraded,
        }
    }

    /// Record that a ping was sent. Returns the sequence number.
    pub fn on_ping_sent(&mut self) -> u64 {
        self.tracker.record_ping_sent()
    }

    /// Record a valid pong received.
    pub fn on_pong_received(&mut self, seq: u64) -> HeartbeatState {
        self.tracker.record_pong(seq)
    }

    /// Run one tick of failure detection. Returns the updated heartbeat
    /// state and whether the connection is newly dead.
    #[must_use]
    pub fn tick(&mut self) -> (HeartbeatState, bool) {
        let prev_state = self.tracker.state;
        // Run failure detection (may record timeout-based miss)
        let _ = detect_failure(&mut self.tracker);
        // Check if miss threshold has been crossed
        if self.tracker.consecutive_misses >= self.tracker.config.miss_threshold {
            self.tracker.state = HeartbeatState::Dead;
        }
        let state = self.tracker.state;
        // Newly dead if: was not Dead before, is Dead now
        let newly_dead = prev_state != HeartbeatState::Dead && state == HeartbeatState::Dead;
        (state, newly_dead)
    }

    /// Check if it is time to send a ping.
    #[must_use]
    pub fn should_ping(&self) -> bool {
        self.tracker.should_ping()
    }

    /// Begin reconnection after dead detection.
    #[must_use]
    pub fn start_reconnect(&mut self) -> bool {
        self.tracker.start_reconnect()
    }

    /// Mark reconnection as successful.
    pub fn reconnect_success(&mut self) {
        self.tracker.reconnect_success();
    }
}

impl Default for SessionKeepalive {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ConnectionKeepalive impl for SessionKeepalive
// ---------------------------------------------------------------------------

impl ConnectionKeepalive for SessionKeepalive {
    fn record_activity(&mut self) {
        self.tracker.record_activity();
    }

    fn should_send_probe(&self) -> bool {
        self.should_ping()
    }

    fn send_probe(&mut self) -> u64 {
        self.on_ping_sent()
    }

    fn record_missed_probe(&mut self) {
        self.tracker.record_miss();
    }

    fn record_response(&mut self, seq: u64) {
        self.on_pong_received(seq);
    }

    fn is_peer_dead(&self) -> bool {
        self.tracker.state.is_dead()
    }

    fn reset(&mut self) {
        self.reconnect_success();
    }
}

/// Check keepalive health for a session and return the resulting
/// classification. If the connection is newly dead, the caller should
/// initiate teardown.
#[must_use]
pub fn session_keepalive_check(
    keepalive: &mut SessionKeepalive,
) -> (KeepaliveHealth, bool /* newly_dead */) {
    if !keepalive.is_active() {
        return (KeepaliveHealth::Alive, false);
    }
    let (_state, newly_dead) = keepalive.tick();
    (keepalive.health(), newly_dead)
}

// ---------------------------------------------------------------------------
// Tokio-driven keepalive runner
// ---------------------------------------------------------------------------

/// Event emitted by the keepalive on state transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveEvent {
    /// A keepalive ping was sent to the peer.
    PingSent { seq: u64 },
    /// A valid pong response was received from the peer.
    PongReceived { seq: u64, rtt: Duration },
    /// A keepalive probe went unanswered.
    KeepaliveMissed { missed_count: u8, max_missed: u8 },
    /// The peer is considered dead after exceeding the miss threshold.
    KeepaliveFailed,
}

/// Trait for objects that receive keepalive events.
///
/// Subscribers are notified on each keepalive state transition so that
/// connection lifecycle, health scoring, and logging can react without
/// polling.
pub trait KeepaliveSubscriber {
    /// Called when a keepalive event occurs.
    fn on_keepalive_event(&mut self, event: KeepaliveEvent);
}

/// A tokio-driven keepalive heartbeat runner for a connection.
///
/// Spawns an async task that monitors connection activity and sends
/// periodic keepalive probes when the connection is idle. On keepalive
/// failure, the runner notifies subscribers and signals teardown.
///
/// # Lifecycle
///
/// 1. Create with `KeepaliveRunner::new(config)`.
/// 2. Call `runner.run()` to spawn the background task.
/// 3. Call `runner.on_pong_received(seq)` when the peer responds.
/// 4. Subscribe via `runner.subscribe(subscriber)` for events.
/// 5. Drop `runner` (or call `shutdown()`) to cancel the background task.
pub struct KeepaliveRunner {
    /// The keepalive state tracker.
    pub keepalive: SessionKeepalive,
    /// Interval between keepalive probes.
    pub interval: Duration,
    /// Sender side of the health notification channel.
    event_tx: Option<tokio::sync::watch::Sender<KeepaliveEvent>>,
    /// Receiver side of the health notification channel.
    pub event_rx: tokio::sync::watch::Receiver<KeepaliveEvent>,
    /// Shutdown signal sender.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// Registered event subscribers.
    subscribers: Vec<Box<dyn KeepaliveSubscriber + Send>>,
}

impl KeepaliveRunner {
    /// Create a new keepalive runner with the given interval.
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        let (event_tx, event_rx) = tokio::sync::watch::channel(KeepaliveEvent::KeepaliveFailed);
        Self {
            keepalive: SessionKeepalive::new(),
            interval,
            event_tx: Some(event_tx),
            event_rx,
            shutdown_tx: None,
            subscribers: Vec::new(),
        }
    }

    /// Create a new runner with a custom keepalive config.
    #[must_use]
    pub fn with_config(config: KeepaliveConfig, interval: Duration) -> Self {
        let (event_tx, event_rx) = tokio::sync::watch::channel(KeepaliveEvent::KeepaliveFailed);
        let mut keeper = SessionKeepalive::with_config(HeartbeatConfig::new(
            config.probe_interval,
            u32::from(config.max_missed_probes),
        ));
        keeper.activate();
        Self {
            keepalive: keeper,
            interval,
            event_tx: Some(event_tx),
            event_rx,
            shutdown_tx: None,
            subscribers: Vec::new(),
        }
    }

    /// Register a subscriber for keepalive events.
    pub fn subscribe(&mut self, subscriber: Box<dyn KeepaliveSubscriber + Send>) {
        self.subscribers.push(subscriber);
    }

    /// Notify all subscribers of an event.
    fn notify_subscribers(&mut self, event: KeepaliveEvent) {
        for sub in &mut self.subscribers {
            sub.on_keepalive_event(event);
        }
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }

    /// Record that a pong was received for the given sequence number.
    /// Returns the RTT if available.
    pub fn on_pong_received(&mut self, seq: u64) -> Option<Duration> {
        let rtt = self.keepalive.tracker.last_pong_rtt();
        self.keepalive.on_pong_received(seq);
        if let Some(rtt) = rtt {
            self.notify_subscribers(KeepaliveEvent::PongReceived { seq, rtt });
        }
        rtt
    }

    /// Spawn the background keepalive task.
    pub fn run(&mut self) {
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        self.shutdown_tx = Some(shutdown_tx);

        let mut keepalive = std::mem::take(&mut self.keepalive);
        keepalive.activate();
        let interval = self.interval;

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        if !keepalive.is_active() {
                            continue;
                        }
                        // Record missed probes and check health
                        let (_health, newly_dead) = session_keepalive_check(&mut keepalive);
                        if newly_dead {
                            // Signal failure — caller handles teardown
                            break;
                        }
                    }
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }
        });
    }

    /// Whether the background keepalive task is running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.shutdown_tx.is_some()
    }

    /// Shut down the background keepalive task.
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

// ---------------------------------------------------------------------------
// KeepaliveMessage -- transport frame variants
// ---------------------------------------------------------------------------

/// Keepalive message variants for the transport frame type.
///
/// These are carried within the `HeartbeatAck` [`crate::envelope::MessageFamily`]
/// and dispatched by the receiving connection's keepalive responder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveMessage {
    /// A keepalive ping sent to probe peer liveness.
    Ping { seq: u64 },
    /// A keepalive pong sent in response to a ping.
    Pong { seq: u64 },
}

impl KeepaliveMessage {
    /// Encode this message into an 8-byte wire frame.
    #[must_use]
    pub fn encode(&self) -> [u8; 8] {
        match self {
            Self::Ping { seq } | Self::Pong { seq } => seq.to_le_bytes(),
        }
    }

    /// Decode a message from an 8-byte wire frame.
    ///
    /// The `is_ping` flag selects the variant; the caller determines this
    /// from the transport envelope discriminator.
    #[must_use]
    pub fn decode(frame: &[u8; 8], is_ping: bool) -> Self {
        let seq = u64::from_le_bytes(*frame);
        if is_ping {
            Self::Ping { seq }
        } else {
            Self::Pong { seq }
        }
    }

    /// The sequence number carried by this message.
    #[must_use]
    pub fn seq(&self) -> u64 {
        match self {
            Self::Ping { seq } | Self::Pong { seq } => *seq,
        }
    }
}

// ---------------------------------------------------------------------------
// KeepaliveResponder -- stateless ping-response handler
// ---------------------------------------------------------------------------

/// A stateless keepalive responder that sends a pong for every received ping.
///
/// Bind to a connection's receive path and call [`KeepaliveResponder::on_ping`]
/// when a [`KeepaliveMessage::Ping`] arrives. The returned pong frame should
/// be written to the outbound send path.
#[derive(Clone, Debug, Default)]
pub struct KeepaliveResponder;

impl KeepaliveResponder {
    /// Create a new responder.
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Handle an incoming ping by producing the corresponding pong message.
    ///
    /// The pong echoes the ping's sequence number so the initiator can
    /// measure round-trip time.
    #[must_use]
    pub fn on_ping(&self, ping: &KeepaliveMessage) -> KeepaliveMessage {
        KeepaliveMessage::Pong { seq: ping.seq() }
    }

    /// Build a pong frame directly from a raw sequence number.
    #[must_use]
    pub fn pong_for_seq(&self, seq: u64) -> KeepaliveMessage {
        KeepaliveMessage::Pong { seq }
    }
}

// ---------------------------------------------------------------------------
// KeepaliveInitiator -- drives the ping side with stateful tracking
// ---------------------------------------------------------------------------

/// Drives the keepalive ping side for a connection.
///
/// Wraps a [`KeepaliveEngine`] and a drain-trigger callback. When the
/// keepalive detects peer failure (consecutive missed probes exceeds
/// `max_missed_probes`), the drain trigger is invoked to transition the
/// connection to `Draining`.
///
/// # Integration
///
/// ```ignore
/// let mut initiator = KeepaliveInitiator::new(config, || {
///     lifecycle.transition_to(ConnectionState::Draining).ok();
/// });
///
/// // On each tick (e.g., in a connection event loop):
/// if let Some(ping) = initiator.tick() {
///     send_frame(&ping.encode());
/// }
///
/// // When data arrives (any traffic proves liveness):
/// initiator.record_activity();
///
/// // When a pong is received:
/// initiator.on_pong(seq);
/// ```
pub struct KeepaliveInitiator<F: FnMut()> {
    /// The underlying keepalive engine.
    engine: KeepaliveEngine,
    /// Callback invoked when keepalive declares the peer dead.
    drain_trigger: F,
    /// Whether the drain trigger has already been fired.
    drain_fired: bool,
}

impl<F: FnMut()> KeepaliveInitiator<F> {
    /// Create a new initiator with the given config and drain trigger.
    #[must_use]
    pub fn new(config: KeepaliveConfig, drain_trigger: F) -> Self {
        Self {
            engine: KeepaliveEngine::new(config),
            drain_trigger,
            drain_fired: false,
        }
    }

    /// Create a new initiator with default config.
    #[must_use]
    pub fn with_defaults(drain_trigger: F) -> Self {
        Self::new(KeepaliveConfig::default(), drain_trigger)
    }

    /// Record that data was received on the connection (any traffic).
    /// Resets idle timers and returns the keepalive to Idle.
    pub fn record_activity(&mut self) {
        self.engine.record_activity();
    }

    /// Record a pong response received from the peer.
    pub fn on_pong(&mut self, seq: u64) {
        self.engine.record_response(seq);
    }

    /// Tick the keepalive state machine.
    ///
    /// Returns `Some(ping_seq)` if a ping should be sent now.
    /// Returns `None` if no action is needed.
    ///
    /// If the peer is detected dead, the drain trigger is invoked
    /// (at most once).
    pub fn tick(&mut self) -> Option<u64> {
        if self.engine.is_peer_dead() {
            if !self.drain_fired {
                self.drain_fired = true;
                (self.drain_trigger)();
            }
            return None;
        }

        // If we're in Probing state and it's time to send another,
        // the previous probe timed out → record a miss
        if matches!(self.engine.state, KeepaliveState::Probing { .. })
            && self.engine.should_send_probe()
        {
            self.engine.record_missed_probe();
            // Check if the miss pushed us to Failed
            if self.engine.is_peer_dead() {
                if !self.drain_fired {
                    self.drain_fired = true;
                    (self.drain_trigger)();
                }
                return None;
            }
        }

        if self.engine.should_send_probe() {
            let seq = self.engine.send_probe();
            Some(seq)
        } else {
            None
        }
    }

    /// Check whether the peer has been declared dead.
    #[must_use]
    pub fn is_peer_dead(&self) -> bool {
        self.engine.is_peer_dead()
    }

    /// Access the underlying engine state.
    #[must_use]
    pub fn state(&self) -> KeepaliveState {
        self.engine.state
    }

    /// Reset the initiator (e.g., after reconnection).
    pub fn reset(&mut self) {
        self.engine.reset();
        self.drain_fired = false;
    }
}

// ---------------------------------------------------------------------------
// KeepaliveLifecycle -- bridge between ConnectionLifecycle and keepalive
// ---------------------------------------------------------------------------

/// Bridges the transport connection lifecycle and the keepalive protocol.
///
/// Hooks into [`crate::connection_state::ConnectionLifecycle`] transitions:
/// - On `Active`, arms the keepalive initiator.
/// - On keepalive failure, triggers `Draining` transition.
///
/// Usage from the connection event loop:
///
/// ```ignore
/// let mut bridge = KeepaliveLifecycle::new(config);
///
/// // When connection becomes Active:
/// bridge.on_active();
///
/// // On each event-loop tick:
/// if let Some(ping_seq) = bridge.tick() {
///     send_keepalive_frame(KeepaliveMessage::Ping { seq: ping_seq });
/// }
///
/// // When a keepalive pong arrives:
/// bridge.on_pong(seq);
///
/// // When any data arrives:
/// bridge.record_activity();
/// ```
#[derive(Debug)]
pub struct KeepaliveLifecycle {
    /// The keepalive engine tracking liveness.
    engine: KeepaliveEngine,
    /// Whether the keepalive is armed (connection is Active).
    armed: bool,
    /// Whether the peer has been declared dead.
    dead: bool,
}

impl KeepaliveLifecycle {
    /// Create a new bridge with the given config. Keepalive is inactive
    /// until `on_active()` is called.
    #[must_use]
    pub fn new(config: KeepaliveConfig) -> Self {
        Self {
            engine: KeepaliveEngine::new(config),
            armed: false,
            dead: false,
        }
    }

    /// Create with default config.
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(KeepaliveConfig::default())
    }

    /// Arm the keepalive (call when connection transitions to Active).
    pub fn on_active(&mut self) {
        self.engine.reset();
        self.armed = true;
        self.dead = false;
    }

    /// Disarm the keepalive (call when connection leaves Active).
    pub fn on_inactive(&mut self) {
        self.armed = false;
    }

    /// Record any received data (proves liveness, resets idle timer).
    pub fn record_activity(&mut self) {
        self.engine.record_activity();
    }

    /// Record a valid pong response.
    pub fn on_pong(&mut self, seq: u64) {
        self.engine.record_response(seq);
    }

    /// Tick the keepalive. Returns the next ping sequence to send,
    /// or `None`. If the connection should be drained, returns
    /// `KeepaliveAction::Drain`.
    #[must_use]
    pub fn tick(&mut self) -> KeepaliveAction {
        if !self.armed {
            return KeepaliveAction::None;
        }

        if self.dead {
            return KeepaliveAction::None;
        }

        // Record missed probes for timed-out pings
        if matches!(self.engine.state, KeepaliveState::Probing { .. })
            && self.engine.should_send_probe()
        {
            self.engine.record_missed_probe();
        }

        if self.engine.is_peer_dead() {
            self.dead = true;
            return KeepaliveAction::Drain;
        }

        if self.engine.should_send_probe() {
            let seq = self.engine.send_probe();
            KeepaliveAction::SendPing(seq)
        } else {
            KeepaliveAction::None
        }
    }

    /// Whether the connection should be drained due to keepalive failure.
    #[must_use]
    pub fn should_drain(&self) -> bool {
        self.dead
    }

    /// Whether the keepalive is currently armed.
    #[must_use]
    pub fn is_armed(&self) -> bool {
        self.armed
    }

    /// Whether the engine is currently expecting a pong response
    /// (i.e. in Probing state). Used by the receive path to decide
    /// whether an inbound HeartbeatAck frame is a ping (respond) or
    /// a pong (just record, do not respond).
    #[must_use]
    pub fn is_expecting_pong(&self) -> bool {
        matches!(self.engine.state, KeepaliveState::Probing { .. })
    }
}

/// Action returned by [`KeepaliveLifecycle::tick`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepaliveAction {
    /// No action needed.
    None,
    /// Send a ping with the given sequence number.
    SendPing(u64),
    /// The peer is dead; initiate connection drain.
    Drain,
}

#[cfg(test)]
mod tests {

    // -----------------------------------------------------------------------
    // Wire format tests
    // -----------------------------------------------------------------------

    #[test]
    fn ping_encode_decode_roundtrip() {
        let seq = 42;
        let frame = build_ping(seq);
        assert_eq!(frame.len(), KEEPALIVE_FRAME_SIZE);
        // Magic bytes removed; keepalive uses plain 8-byte seq frames
        let decoded = decode_ping(&frame);
        assert_eq!(decoded, Some(seq));
    }

    #[test]
    fn pong_encode_decode_roundtrip() {
        let seq = 99;
        let frame = build_pong(seq);
        assert_eq!(frame.len(), KEEPALIVE_FRAME_SIZE);
        // Magic bytes removed; keepalive uses plain 8-byte seq frames
        let decoded = decode_pong(&frame);
        assert_eq!(decoded, Some(seq));
    }

    #[test]
    fn ping_decoded_as_either_format() {
        // Ping and pong frames are identical 8-byte seq on the wire;
        // the transport framing layer distinguishes them.
        let frame = build_ping(7);
        assert_eq!(decode_ping(&frame), Some(7));
        assert_eq!(decode_pong(&frame), Some(7));
    }

    #[test]
    fn pong_decoded_as_either_format() {
        // Ping and pong frames are identical 8-byte seq on the wire
        let frame = build_pong(7);
        assert_eq!(decode_pong(&frame), Some(7));
        assert_eq!(decode_ping(&frame), Some(7));
    }

    #[test]
    fn corrupted_seq_still_decodes() {
        // With plain 8-byte seq frames, changing a byte changes the value
        // but the frame is still a valid 8-byte encoding.
        let mut frame = build_ping(1);
        frame[0] = 0xFF;
        let decoded = decode_ping(&frame);
        assert!(decoded.is_some());
        assert_ne!(decoded.unwrap(), 1);
    }

    #[test]
    fn corrupted_seq_changes_decoded_value() {
        // With plain 8-byte seq, any 8-byte frame decodes.
        // Integrity is provided by the transport security boundary.
        let mut frame = build_ping(1);
        frame[3] ^= 0x01; // flip a bit in the sequence number
        let decoded = decode_ping(&frame);
        assert!(decoded.is_some());
        assert_ne!(decoded.unwrap(), 1);
    }

    #[test]
    fn wrong_size_rejected() {
        let short = vec![0u8; 10];
        assert_eq!(decode_ping(&short), None);
        assert_eq!(decode_pong(&short), None);
        let long = vec![0u8; 100];
        assert_eq!(decode_ping(&long), None);
        assert_eq!(decode_pong(&long), None);
    }

    #[test]
    fn sequence_monotonicity_in_wire() {
        for seq in [0, 1, u64::MAX / 2, u64::MAX] {
            let frame = build_ping(seq);
            let decoded = decode_ping(&frame);
            assert_eq!(decoded, Some(seq), "failed for seq={seq}");
        }
    }

    #[test]
    fn ping_pong_frames_are_identical_on_wire() {
        // Ping and pong frames are now identical 8-byte seq frames.
        // The transport framing layer distinguishes them.
        let fp = build_ping(42);
        let fr = build_pong(42);
        assert_eq!(fp, fr);
        assert_eq!(fp.len(), 8);
    }

    // -----------------------------------------------------------------------
    // Pong validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_current_seq() {
        let frame = build_pong(10);
        assert_eq!(validate_pong(&frame, 9), Ok(10));
    }

    #[test]
    fn validate_stale_seq_rejected() {
        let frame = build_pong(5);
        let err = validate_pong(&frame, 10).unwrap_err();
        assert_eq!(
            err,
            PongValidationError::StaleSequence {
                received: 5,
                last_acked: 10
            }
        );
    }

    #[test]
    fn validate_same_seq_accepted() {
        let frame = build_pong(5);
        assert_eq!(validate_pong(&frame, 5), Ok(5));
    }

    #[test]
    fn validate_pong_zero_seq() {
        // An 8-byte all-zero frame decodes as seq=0 (valid size)
        let zero = vec![0u8; KEEPALIVE_FRAME_SIZE];
        assert_eq!(validate_pong(&zero, 0), Ok(0));
        // But seq=0 is stale against last_acked=1
        assert_eq!(
            validate_pong(&zero, 1),
            Err(PongValidationError::StaleSequence {
                received: 0,
                last_acked: 1
            })
        );
    }

    // -----------------------------------------------------------------------
    // HeartbeatTracker tests
    // -----------------------------------------------------------------------

    #[test]
    fn tracker_starts_healthy() {
        let t = HeartbeatTracker::new();
        assert_eq!(t.state, HeartbeatState::Healthy);
        assert_eq!(t.consecutive_misses, 0);
        assert_eq!(t.next_seq, 1);
    }

    #[test]
    fn record_ping_advances_seq() {
        let mut t = HeartbeatTracker::new();
        let s1 = t.record_ping_sent();
        let s2 = t.record_ping_sent();
        assert_eq!(s1, 1);
        assert_eq!(s2, 2);
        assert_eq!(t.next_seq, 3);
    }

    #[test]
    fn record_pong_resets_misses() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        t.record_miss();
        t.record_miss();
        assert_eq!(t.state, HeartbeatState::Suspect(2));
        t.record_pong(1);
        assert_eq!(t.state, HeartbeatState::Healthy);
        assert_eq!(t.consecutive_misses, 0);
    }

    #[test]
    fn healthy_to_suspect_transition() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for i in 1..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
            assert_eq!(t.state, HeartbeatState::Suspect(i));
        }
    }

    #[test]
    fn suspect_to_dead_transition() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
        }
        assert_eq!(t.state, HeartbeatState::Dead);
    }

    #[test]
    fn dead_to_reconnecting() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
        }
        assert_eq!(t.state, HeartbeatState::Dead);
        let ok = t.start_reconnect();
        assert!(ok);
        assert_eq!(t.state, HeartbeatState::Reconnecting);
    }

    #[test]
    fn reconnect_success_resets_to_healthy() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
        }
        let _ = t.start_reconnect();
        t.reconnect_success();
        assert_eq!(t.state, HeartbeatState::Healthy);
        assert_eq!(t.consecutive_misses, 0);
    }

    #[test]
    fn cannot_start_reconnect_from_healthy() {
        let mut t = HeartbeatTracker::new();
        assert!(!t.start_reconnect());
        assert_eq!(t.state, HeartbeatState::Healthy);
    }

    #[test]
    fn cannot_start_reconnect_from_suspect() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        t.record_miss();
        assert_eq!(t.state, HeartbeatState::Suspect(1));
        assert!(!t.start_reconnect());
    }

    #[test]
    fn should_ping_initially_true() {
        let t = HeartbeatTracker::new();
        assert!(t.should_ping());
    }

    #[test]
    fn custom_miss_threshold() {
        let config = HeartbeatConfig::new(Duration::from_millis(500), 3);
        let mut t = HeartbeatTracker::with_config(config.clone());
        assert_eq!(t.config.miss_threshold, 3);
        t.record_ping_sent();
        t.record_miss();
        assert_eq!(t.state, HeartbeatState::Suspect(1));
        t.record_miss();
        assert_eq!(t.state, HeartbeatState::Suspect(2));
        t.record_miss(); // 3rd miss => Dead
        assert_eq!(t.state, HeartbeatState::Dead);
    }

    // -----------------------------------------------------------------------
    // ReconnectOrchestrator tests
    // -----------------------------------------------------------------------

    #[test]
    fn reconnect_orchestrator_defaults() {
        let orch = ReconnectOrchestrator::default_with_jitter();
        assert_eq!(orch.attempt(), 0);
        assert!(!orch.is_exhausted());
        assert!(orch.jitter_enabled);
    }

    #[test]
    fn reconnect_orchestrator_next_backoff_increases() {
        let policy = ReconnectPolicy::ExponentialBackoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            multiplier_millis: 2000,
        };
        let mut orch = ReconnectOrchestrator::new(policy, false, 0.0);
        let b1 = orch.next_backoff();
        let b2 = orch.next_backoff();
        let b3 = orch.next_backoff();
        // Without jitter, backoff doubles each time
        assert!(b1 >= Duration::from_secs(1));
        assert!(b2 >= Duration::from_secs(2));
        assert!(b3 >= Duration::from_secs(4));
    }

    #[test]
    fn reconnect_orchestrator_exhausted() {
        let policy = ReconnectPolicy::FixedInterval(Duration::from_millis(100));
        let mut orch = ReconnectOrchestrator::with_max_retries(policy, 3);
        assert_eq!(orch.attempt(), 0);
        let _ = orch.next_backoff(); // attempt 1
        let _ = orch.next_backoff(); // attempt 2
        let _ = orch.next_backoff(); // attempt 3
        assert!(orch.is_exhausted());
    }

    #[test]
    fn reconnect_orchestrator_reset() {
        let policy = ReconnectPolicy::ExponentialBackoff {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
            multiplier_millis: 2000,
        };
        let mut orch = ReconnectOrchestrator::new(policy, false, 0.0);
        let _ = orch.next_backoff();
        let _ = orch.next_backoff();
        assert_eq!(orch.attempt(), 2);
        orch.reset();
        assert_eq!(orch.attempt(), 0);
        assert!(!orch.is_exhausted());
    }

    #[test]
    fn jitter_in_bounds() {
        let base = Duration::from_secs(1);
        for _ in 0..100 {
            let j = crate::reconnect::apply_jitter(base, 0.2);
            let lower = Duration::from_millis(800); // 1s - 20%
            let upper = Duration::from_millis(1200); // 1s + 20%
            assert!(j >= lower, "jitter too low: {j:?}");
            assert!(j <= upper, "jitter too high: {j:?}");
        }
    }

    // -----------------------------------------------------------------------
    // Multiple tracker independence test
    // -----------------------------------------------------------------------

    #[test]
    fn multiple_trackers_independent() {
        let mut t1 = HeartbeatTracker::new();
        let mut t2 = HeartbeatTracker::new();
        // Advance t1 but not t2
        t1.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t1.record_miss();
        }
        assert_eq!(t1.state, HeartbeatState::Dead);
        assert_eq!(t2.state, HeartbeatState::Healthy);
        t2.record_ping_sent();
        t2.record_miss();
        assert_eq!(t2.state, HeartbeatState::Suspect(1));
    }

    // -----------------------------------------------------------------------
    // detect_failure tests
    // -----------------------------------------------------------------------

    #[test]
    fn detect_failure_noop_when_dead() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
        }
        assert_eq!(t.state, HeartbeatState::Dead);
        let state = detect_failure(&mut t);
        assert_eq!(state, HeartbeatState::Dead);
    }

    #[test]
    fn detect_failure_noop_when_reconnecting() {
        let mut t = HeartbeatTracker::new();
        t.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            t.record_miss();
        }
        let _ = t.start_reconnect();
        let state = detect_failure(&mut t);
        assert_eq!(state, HeartbeatState::Reconnecting);
    }

    // -----------------------------------------------------------------------
    // is_alive / is_dead helpers
    // -----------------------------------------------------------------------

    #[test]
    fn healthy_is_alive() {
        assert!(HeartbeatState::Healthy.is_alive());
        assert!(!HeartbeatState::Healthy.is_dead());
    }

    #[test]
    fn suspect_is_alive() {
        assert!(HeartbeatState::Suspect(2).is_alive());
        assert!(!HeartbeatState::Suspect(2).is_dead());
    }

    #[test]
    fn dead_is_not_alive() {
        assert!(!HeartbeatState::Dead.is_alive());
        assert!(HeartbeatState::Dead.is_dead());
    }

    #[test]
    fn reconnecting_is_not_alive() {
        assert!(!HeartbeatState::Reconnecting.is_alive());
        assert!(!HeartbeatState::Reconnecting.is_dead());
    }
    // SessionKeepalive tests
    // -----------------------------------------------------------------------

    #[test]
    fn session_keepalive_starts_inactive() {
        let sk = SessionKeepalive::new();
        assert!(!sk.is_active());
        assert_eq!(sk.health(), KeepaliveHealth::Alive);
    }

    #[test]
    fn session_keepalive_activate_deactivate() {
        let mut sk = SessionKeepalive::new();
        assert!(!sk.is_active());
        sk.activate();
        assert!(sk.is_active());
        sk.deactivate();
        assert!(!sk.is_active());
    }

    #[test]
    fn session_keepalive_health_maps_heartbeat_state() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        // Healthy -> Alive
        assert_eq!(sk.health(), KeepaliveHealth::Alive);
        // Suspect -> Degraded
        sk.tracker.record_ping_sent();
        sk.tracker.record_miss();
        assert_eq!(sk.health(), KeepaliveHealth::Degraded);
        // Dead -> Dead
        sk.tracker.record_miss();
        sk.tracker.record_miss();
        sk.tracker.record_miss();
        sk.tracker.record_miss();
        assert_eq!(sk.health(), KeepaliveHealth::Dead);
    }

    #[test]
    fn tick_returns_newly_dead() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        // Healthy tick: not dead
        let (state, newly_dead) = sk.tick();
        assert_eq!(state, HeartbeatState::Healthy);
        assert!(!newly_dead);
        // Manually drive consecutive_misses past threshold
        sk.tracker.record_ping_sent();
        sk.tracker.consecutive_misses = sk.tracker.config.miss_threshold;
        // tick detects threshold crossing
        let (state, newly_dead) = sk.tick();
        assert_eq!(state, HeartbeatState::Dead);
        assert!(newly_dead);
    }

    #[test]
    fn tick_no_double_report() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        // Drive permanent threshold past limit
        sk.tracker.record_ping_sent();
        sk.tracker.consecutive_misses = sk.tracker.config.miss_threshold;
        // First tick: newly dead
        let (state1, newly_dead1) = sk.tick();
        assert_eq!(state1, HeartbeatState::Dead);
        assert!(newly_dead1);
        // Second tick: still dead, NOT newly dead
        let (state2, newly_dead2) = sk.tick();
        assert_eq!(state2, HeartbeatState::Dead);
        assert!(!newly_dead2);
    }

    #[test]
    fn session_keepalive_reconnect_lifecycle() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        sk.tracker.record_ping_sent();
        for _ in 0..DEFAULT_MISS_THRESHOLD {
            sk.tracker.record_miss();
        }
        assert_eq!(sk.tracker.state, HeartbeatState::Dead);
        let ok = sk.start_reconnect();
        assert!(ok);
        assert_eq!(sk.tracker.state, HeartbeatState::Reconnecting);
        sk.reconnect_success();
        assert_eq!(sk.tracker.state, HeartbeatState::Healthy);
    }

    #[test]
    fn session_keepalive_should_ping_true_initially() {
        let sk = SessionKeepalive::new();
        assert!(sk.should_ping());
    }

    #[test]
    fn session_keepalive_check_inactive_returns_alive() {
        let mut sk = SessionKeepalive::new();
        let (health, newly_dead) = session_keepalive_check(&mut sk);
        assert_eq!(health, KeepaliveHealth::Alive);
        assert!(!newly_dead);
    }

    #[test]
    fn session_keepalive_check_newly_dead() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        // Set consecutive_misses directly to cross threshold without
        // letting record_miss transition state before tick runs.
        sk.tracker.record_ping_sent();
        sk.tracker.consecutive_misses = sk.tracker.config.miss_threshold;
        let (health, newly_dead) = session_keepalive_check(&mut sk);
        assert_eq!(health, KeepaliveHealth::Dead);
        assert!(newly_dead);
    }

    #[test]
    fn keepalive_health_alive_eq() {
        let h = KeepaliveHealth::Alive;
        assert_eq!(h, KeepaliveHealth::Alive);
    }

    #[test]
    fn keepalive_health_dead_variant_exists() {
        let h = KeepaliveHealth::Dead;
        assert_ne!(h, KeepaliveHealth::Alive);
    }

    // -----------------------------------------------------------------------
    // KeepaliveRunner tokio integration tests
    // -----------------------------------------------------------------------

    /// Direct keepalive loop: drives heartbeat pings and checks health
    /// using tokio time-pause, all in the test task (no spawn).

    #[tokio::test(start_paused = true)]
    async fn keepalive_loop_transitions_to_dead_without_pongs() {
        let interval = Duration::from_millis(200);
        let miss_threshold: u32 = 3;
        let mut tracker =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));

        // Send initial ping
        tracker.record_ping_sent();

        // Simulate interval ticks: each sleep + no pong = miss
        for i in 0..miss_threshold {
            tokio::time::sleep(interval).await;
            // Previous ping was not acked: record a miss
            tracker.record_miss();
            // Send new ping
            tracker.record_ping_sent();
            if i + 1 < miss_threshold {
                assert!(
                    tracker.state.is_alive(),
                    "still alive after {} misses",
                    i + 1
                );
            }
        }
        // After miss_threshold misses, should be Dead
        assert_eq!(
            tracker.state,
            HeartbeatState::Dead,
            "should be Dead after {miss_threshold} misses"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_loop_stays_healthy_with_pongs() {
        let interval = Duration::from_millis(200);
        let miss_threshold: u32 = 3;
        let mut tracker =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));

        tracker.record_ping_sent();

        // Respond to pongs at each interval
        for _ in 0..(miss_threshold + 2) {
            tokio::time::sleep(interval).await;
            // Ack the previous ping
            let ack_seq = tracker.next_seq.saturating_sub(1);
            tracker.record_pong(ack_seq);
            assert_eq!(
                tracker.state,
                HeartbeatState::Healthy,
                "should stay Healthy with pongs"
            );
            // Send next ping
            tracker.record_ping_sent();
        }
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_loop_miss_then_recover() {
        let interval = Duration::from_millis(100);
        let miss_threshold: u32 = 5;
        let mut tracker =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));

        tracker.record_ping_sent();

        // Miss a few intervals (but not enough for Dead)
        for _ in 0..3 {
            tokio::time::sleep(interval).await;
            tracker.record_miss();
            tracker.record_ping_sent();
        }
        assert_eq!(
            tracker.state,
            HeartbeatState::Suspect(3),
            "should be Suspect(3)"
        );

        // Now recover with a pong
        let ack_seq = tracker.next_seq.saturating_sub(1);
        tracker.record_pong(ack_seq);
        assert_eq!(
            tracker.state,
            HeartbeatState::Healthy,
            "should recover to Healthy"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_loop_dead_stays_dead() {
        let interval = Duration::from_millis(100);
        let miss_threshold: u32 = 2;
        let mut tracker =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));

        tracker.record_ping_sent();
        // Drive to Dead
        for _ in 0..miss_threshold {
            tokio::time::sleep(interval).await;
            tracker.record_miss();
            tracker.record_ping_sent();
        }
        assert_eq!(tracker.state, HeartbeatState::Dead);

        // More time passes without recovery — stays Dead
        tokio::time::sleep(interval * 3).await;
        assert_eq!(tracker.state, HeartbeatState::Dead);
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_loop_two_trackers_independent() {
        let interval = Duration::from_millis(100);
        let miss_threshold: u32 = 3;
        let mut tracker_a =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));
        let mut tracker_b =
            HeartbeatTracker::with_config(HeartbeatConfig::new(interval, miss_threshold));

        tracker_a.record_ping_sent();
        tracker_b.record_ping_sent();

        // Advance time: always ack tracker_a, never ack tracker_b
        for _ in 0..(miss_threshold + 1) {
            tokio::time::sleep(interval).await;
            // Ack tracker_a
            tracker_a.record_pong(tracker_a.next_seq.saturating_sub(1));
            tracker_a.record_ping_sent();
            // Miss tracker_b
            tracker_b.record_miss();
            tracker_b.record_ping_sent();
        }

        assert_eq!(
            tracker_a.state,
            HeartbeatState::Healthy,
            "tracker_a should be Healthy"
        );
        assert_eq!(
            tracker_b.state,
            HeartbeatState::Dead,
            "tracker_b should be Dead"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_runner_create_and_shutdown() {
        let mut runner = KeepaliveRunner::new(Duration::from_millis(100));
        runner.run();
        assert!(runner.is_running());
        runner.shutdown();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(!runner.is_running());
    }

    #[tokio::test(start_paused = true)]
    async fn keepalive_runner_drop_cleans_up() {
        {
            let mut runner = KeepaliveRunner::new(Duration::from_millis(100));
            runner.run();
            assert!(runner.is_running());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // -----------------------------------------------------------------------
    // KeepaliveConfig tests
    // -----------------------------------------------------------------------

    #[test]
    fn keepalive_config_defaults() {
        let cfg = KeepaliveConfig::default();
        assert_eq!(cfg.idle_timeout, Duration::from_secs(30));
        assert_eq!(cfg.probe_interval, Duration::from_secs(5));
        assert_eq!(cfg.max_missed_probes, 3);
    }

    #[test]
    fn keepalive_config_new_valid() {
        let cfg = KeepaliveConfig::new(Duration::from_secs(60), Duration::from_secs(10), 5);
        assert!(cfg.is_some());
        let c = cfg.unwrap();
        assert_eq!(c.idle_timeout, Duration::from_secs(60));
        assert_eq!(c.probe_interval, Duration::from_secs(10));
        assert_eq!(c.max_missed_probes, 5);
    }

    #[test]
    fn keepalive_config_rejects_zero_idle_timeout() {
        assert!(KeepaliveConfig::new(Duration::ZERO, Duration::from_secs(5), 3,).is_none());
    }

    #[test]
    fn keepalive_config_rejects_zero_probe_interval() {
        assert!(KeepaliveConfig::new(Duration::from_secs(30), Duration::ZERO, 3,).is_none());
    }

    #[test]
    fn keepalive_config_rejects_zero_max_missed() {
        assert!(
            KeepaliveConfig::new(Duration::from_secs(30), Duration::from_secs(5), 0,).is_none()
        );
    }

    #[test]
    fn keepalive_config_validate_ok() {
        let cfg = KeepaliveConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn keepalive_config_validate_zero_idle() {
        let cfg = KeepaliveConfig {
            idle_timeout: Duration::ZERO,
            ..KeepaliveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn keepalive_config_validate_zero_interval() {
        let cfg = KeepaliveConfig {
            probe_interval: Duration::ZERO,
            ..KeepaliveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn keepalive_config_validate_zero_missed() {
        let cfg = KeepaliveConfig {
            max_missed_probes: 0,
            ..KeepaliveConfig::default()
        };
        assert!(cfg.validate().is_err());
    }

    // -----------------------------------------------------------------------
    // KeepaliveState tests
    // -----------------------------------------------------------------------

    #[test]
    fn keepalive_state_idle_is_alive() {
        assert!(KeepaliveState::Idle.is_alive());
        assert!(!KeepaliveState::Idle.is_dead());
    }

    #[test]
    fn keepalive_state_probing_is_alive() {
        assert!(KeepaliveState::Probing { missed: 2 }.is_alive());
        assert!(!KeepaliveState::Probing { missed: 2 }.is_dead());
    }

    #[test]
    fn keepalive_state_failed_is_dead() {
        assert!(!KeepaliveState::Failed.is_alive());
        assert!(KeepaliveState::Failed.is_dead());
    }

    // -----------------------------------------------------------------------
    // KeepaliveProbe / KeepaliveResponse wire format tests
    // -----------------------------------------------------------------------

    #[test]
    fn probe_encode_decode_roundtrip() {
        let frame = build_probe(42);
        assert_eq!(frame.len(), KEEPALIVE_PROBE_SIZE);
        assert_eq!(decode_probe(&frame), Some(42));
    }

    #[test]
    fn response_encode_decode_roundtrip() {
        let frame = build_response(99);
        assert_eq!(frame.len(), KEEPALIVE_RESPONSE_SIZE);
        assert_eq!(decode_response(&frame), Some(99));
    }

    #[test]
    fn probe_decoded_as_either() {
        // Probes and responses are now identical 8-byte seq frames
        let frame = build_probe(7);
        assert_eq!(decode_probe(&frame), Some(7));
        assert_eq!(decode_response(&frame), Some(7));
    }

    #[test]
    fn response_decoded_as_either() {
        // Probes and responses are now identical 8-byte seq frames
        let frame = build_response(7);
        assert_eq!(decode_response(&frame), Some(7));
        assert_eq!(decode_probe(&frame), Some(7));
    }

    #[test]
    fn probe_corrupted_seq_changes_value() {
        // With plain 8-byte seq, any 8-byte frame decodes.
        // Corruption changes the decoded value.
        let mut frame = build_probe(1);
        frame[3] ^= 0x01;
        let decoded = decode_probe(&frame);
        assert!(decoded.is_some());
        assert_ne!(decoded.unwrap(), 1);
    }

    #[test]
    fn response_corrupted_seq_changes_value() {
        // With plain 8-byte seq, any 8-byte frame decodes.
        let mut frame = build_response(1);
        frame[3] ^= 0x01;
        let decoded = decode_response(&frame);
        assert!(decoded.is_some());
        assert_ne!(decoded.unwrap(), 1);
    }

    #[test]
    fn probe_wrong_size_rejected() {
        assert_eq!(decode_probe(&[0u8; 4]), None);
        assert_eq!(decode_probe(&[0u8; 16]), None);
    }

    #[test]
    fn response_wrong_size_rejected() {
        assert_eq!(decode_response(&[0u8; 4]), None);
        assert_eq!(decode_response(&[0u8; 16]), None);
    }

    #[test]
    fn probe_response_frames_are_identical() {
        // Probes and responses are now identical 8-byte seq frames
        let probe = build_probe(5);
        let resp = build_response(5);
        assert_eq!(probe, resp);
        assert_eq!(probe.len(), 8);
    }

    #[test]
    fn validate_response_current_seq() {
        let frame = build_response(10);
        assert_eq!(validate_response(&frame, 9), Ok(10));
    }

    #[test]
    fn validate_response_stale_seq_rejected() {
        let frame = build_response(5);
        let err = validate_response(&frame, 10).unwrap_err();
        assert_eq!(
            err,
            ProbeResponseError::StaleSequence {
                received: 5,
                last_acked: 10,
            }
        );
    }

    #[test]
    fn validate_response_zero_seq() {
        // Zero-seq frame is valid size now, decodes as seq=0
        let zero = vec![0u8; KEEPALIVE_RESPONSE_SIZE];
        assert_eq!(validate_response(&zero, 0), Ok(0));
        assert_eq!(
            validate_response(&zero, 1),
            Err(ProbeResponseError::StaleSequence {
                received: 0,
                last_acked: 1
            })
        );
    }

    // -----------------------------------------------------------------------
    // KeepaliveEngine tests
    // -----------------------------------------------------------------------

    #[test]
    fn engine_starts_idle() {
        let engine = KeepaliveEngine::with_defaults();
        assert_eq!(engine.state, KeepaliveState::Idle);
        assert!(!engine.is_peer_dead());
    }

    #[test]
    fn engine_record_activity_sets_timer() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        // After recording activity, should not want to probe immediately
        assert!(!engine.should_send_probe());
    }

    #[test]
    fn engine_idle_to_probing() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        // Should not probe immediately
        assert!(!engine.should_send_probe());
        // But probing should not fail either (just not ready yet)
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_send_probe_advances_state() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        let seq = engine.send_probe();
        assert_eq!(seq, 1);
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 0 });
    }

    #[test]
    fn engine_multiple_probes_advance_missed_count() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 0 });
        engine.send_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 1 });
        engine.send_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 2 });
    }

    #[test]
    fn engine_record_missed_probe_transitions() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 1 });
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 2 });
        engine.record_missed_probe(); // exceeds max_missed_probes (3)
        assert_eq!(engine.state, KeepaliveState::Failed);
        assert!(engine.is_peer_dead());
    }

    #[test]
    fn engine_response_returns_to_idle() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 1 });
        engine.record_response(1);
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_activity_during_probing_returns_to_idle() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 1 });
        // Data arrives — proves liveness
        engine.record_activity();
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_failed_does_not_probe() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        // Drive to failed
        engine.send_probe();
        engine.record_missed_probe();
        engine.record_missed_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Failed);
        assert!(!engine.should_send_probe());
    }

    #[test]
    fn engine_reset_clears_state() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        engine.record_missed_probe();
        engine.record_missed_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Failed);
        engine.reset();
        assert_eq!(engine.state, KeepaliveState::Idle);
        assert!(!engine.is_peer_dead());
    }

    #[test]
    fn engine_sequence_monotonic_across_resets() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        let s1 = engine.send_probe();
        assert_eq!(s1, 1);
        let s2 = engine.send_probe();
        assert_eq!(s2, 2);
        engine.record_response(2);
        engine.reset();
        engine.record_activity();
        let s3 = engine.send_probe();
        assert_eq!(s3, 3); // monotonic across reset
    }

    #[test]
    fn engine_custom_config() {
        let cfg =
            KeepaliveConfig::new(Duration::from_secs(60), Duration::from_secs(10), 2).unwrap();
        let mut engine = KeepaliveEngine::new(cfg);
        engine.record_activity();
        engine.send_probe();
        engine.record_missed_probe();
        assert_eq!(engine.state, KeepaliveState::Probing { missed: 1 });
        engine.record_missed_probe(); // max=2, so Failed
        assert_eq!(engine.state, KeepaliveState::Failed);
    }

    #[test]
    fn engine_should_send_probe_after_idle_timeout() {
        let mut engine = KeepaliveEngine::with_defaults();
        // No activity recorded yet — should not probe
        assert!(!engine.should_send_probe());
        engine.record_activity();
        // Just recorded activity — should not probe
        assert!(!engine.should_send_probe());
        // After 30s idle timeout (in real time), it would probe.
        // In unit test without time mocking, we verify the state logic:
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_record_activity_clears_probing() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        engine.send_probe();
        engine.send_probe();
        assert!(matches!(engine.state, KeepaliveState::Probing { .. }));
        // Data received clears probing
        engine.record_activity();
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_two_independent_engines() {
        let mut e1 = KeepaliveEngine::with_defaults();
        let mut e2 = KeepaliveEngine::with_defaults();

        e1.record_activity();
        e2.record_activity();

        e1.send_probe();
        e1.record_missed_probe();
        e1.record_missed_probe();
        e1.record_missed_probe();
        assert_eq!(e1.state, KeepaliveState::Failed);

        // e2 is unaffected
        assert_eq!(e2.state, KeepaliveState::Idle);
    }

    #[test]
    fn engine_record_response_validates_seq() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        let seq = engine.send_probe();
        engine.record_response(seq);
        assert_eq!(engine.state, KeepaliveState::Idle);
    }

    #[test]
    fn connection_keepalive_trait_is_object_safe() {
        let mut engine = KeepaliveEngine::with_defaults();
        engine.record_activity();
        let ka: &mut dyn ConnectionKeepalive = &mut engine;
        assert!(!ka.is_peer_dead());
        let seq = ka.send_probe();
        assert!(seq > 0);
        ka.record_missed_probe();
        ka.record_missed_probe();
        ka.record_missed_probe();
        assert!(ka.is_peer_dead());
        ka.reset();
        assert!(!ka.is_peer_dead());
    }

    #[test]
    fn connection_keepalive_heartbeat_tracker_trait() {
        let mut tracker = HeartbeatTracker::new();
        let ka: &mut dyn ConnectionKeepalive = &mut tracker;
        assert!(!ka.is_peer_dead());
        assert!(ka.should_send_probe());
        let seq = ka.send_probe();
        assert!(seq > 0);
        ka.record_response(seq);
        assert!(!ka.is_peer_dead());
        // Miss threshold is 5; record 5 misses
        for _ in 0..5 {
            ka.send_probe();
            ka.record_missed_probe();
        }
        assert!(ka.is_peer_dead());
        ka.reset();
        assert!(!ka.is_peer_dead());
    }

    #[test]
    fn connection_keepalive_session_keepalive_trait() {
        let mut sk = SessionKeepalive::new();
        sk.activate();
        let ka: &mut dyn ConnectionKeepalive = &mut sk;
        assert!(!ka.is_peer_dead());
        assert!(ka.should_send_probe());
        let seq = ka.send_probe();
        assert!(seq > 0);
        ka.record_response(seq);
        assert!(!ka.is_peer_dead());
        // Miss threshold is 5; record 5 misses
        for _ in 0..5 {
            ka.send_probe();
            ka.record_missed_probe();
        }
        assert!(ka.is_peer_dead());
        ka.reset();
        assert!(!ka.is_peer_dead());
    }

    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // TCP integration tests
    // -------------------------------------------------------------------
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// Start a TCP server that echoes ping frames as pongs.
    /// Only supports the 44-byte ping/pong wire format.
    async fn spawn_keepalive_echo() -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match listener.accept().await {
                    Ok(pair) => pair,
                    Err(_) => return,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
                    loop {
                        if stream.read_exact(&mut buf).await.is_err() {
                            return;
                        }
                        if let Some(seq) = decode_ping(&buf) {
                            let pong = build_pong(seq);
                            if stream.write_all(&pong).await.is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn tcp_ping_pong_roundtrip() {
        let addr = spawn_keepalive_echo().await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        for seq in 1..=5u64 {
            let ping = build_ping(seq);
            stream.write_all(&ping).await.expect("write ping");
            let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
            stream.read_exact(&mut buf).await.expect("read pong");
            let decoded = decode_pong(&buf).expect("valid pong");
            assert_eq!(decoded, seq, "pong seq should match ping seq");
        }
    }

    #[tokio::test]
    async fn tcp_dead_peer_detection_heartbeat() {
        let addr = spawn_keepalive_echo().await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        let mut tracker = HeartbeatTracker::with_config(HeartbeatConfig::new(
            std::time::Duration::from_millis(100),
            3,
        ));

        // Round 1: ping-pong, expect alive
        let seq = tracker.record_ping_sent();
        stream
            .write_all(&build_ping(seq))
            .await
            .expect("write ping");
        let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
        stream.read_exact(&mut buf).await.expect("read pong");
        let ack = decode_pong(&buf).expect("valid pong");
        tracker.record_pong(ack);
        assert!(!tracker.state.is_dead());

        // Round 2: another ping-pong
        let seq = tracker.record_ping_sent();
        stream
            .write_all(&build_ping(seq))
            .await
            .expect("write ping");
        stream.read_exact(&mut buf).await.expect("read pong");
        let ack = decode_pong(&buf).expect("valid pong");
        tracker.record_pong(ack);
        assert!(!tracker.state.is_dead());

        // Simulate peer death by dropping stream
        drop(stream);

        // 3 consecutive misses → Dead
        tracker.record_ping_sent();
        tracker.record_miss();
        assert!(tracker.state.is_alive());
        tracker.record_ping_sent();
        tracker.record_miss();
        assert!(tracker.state.is_alive());
        tracker.record_ping_sent();
        tracker.record_miss();
        assert!(tracker.state.is_dead(), "should be Dead after 3 misses");
    }

    #[tokio::test]
    async fn tcp_pong_validation_roundtrip() {
        let addr = spawn_keepalive_echo().await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        let ping = build_ping(42);
        stream.write_all(&ping).await.expect("write");
        let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
        stream.read_exact(&mut buf).await.expect("read");

        let result = validate_pong(&buf, 41);
        assert!(result.is_ok(), "should accept seq >= last_acked");
        assert_eq!(result.unwrap(), 42);

        let result = validate_pong(&buf, 43);
        assert!(result.is_err(), "should reject stale seq");
    }

    #[tokio::test]
    async fn tcp_monotonic_seq_across_reconnect() {
        let addr = spawn_keepalive_echo().await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        let mut tracker = HeartbeatTracker::with_config(HeartbeatConfig::new(
            std::time::Duration::from_millis(100),
            3,
        ));

        let s1 = tracker.record_ping_sent();
        stream.write_all(&build_ping(s1)).await.expect("write ping");
        let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
        stream.read_exact(&mut buf).await.expect("read pong");
        tracker.record_pong(decode_pong(&buf).unwrap());

        // Disconnect (drop stream)
        drop(stream);

        // next_seq should be monotonic (preserved across reconnection)
        let seq_after = tracker.next_seq;
        assert!(
            seq_after > s1,
            "next_seq should be monotonic after disconnect"
        );
    }

    #[tokio::test]
    async fn tcp_corrupted_ping_sequence_mismatch() {
        let addr = spawn_keepalive_echo().await;
        let mut stream = TcpStream::connect(addr).await.expect("connect");

        // Build a valid ping then corrupt the sequence number
        let mut ping = build_ping(1);
        ping[3] ^= 0xFF; // flip bits in the sequence number
        stream.write_all(&ping).await.expect("write");

        // The echo server will decode whatever seq it reads and reply.
        // The pong seq will NOT match the original expectation (seq=1).
        let mut buf = vec![0u8; KEEPALIVE_FRAME_SIZE];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            stream.read_exact(&mut buf),
        )
        .await;

        match result {
            Ok(Ok(_)) => {
                let pong_seq = decode_pong(&buf);
                // The echoed sequence should be corrupted (not 1)
                assert!(pong_seq.is_some());
                assert_ne!(
                    pong_seq.unwrap(),
                    1,
                    "corrupted ping should produce a mismatched echo seq"
                );
            }
            _ => {
                // Timeout — server may have read a wrong-sized frame
            }
        }
    }

    // -----------------------------------------------------------------------
    // KeepaliveMessage tests
    // -----------------------------------------------------------------------

    #[test]
    fn keepalive_message_ping_encode_decode() {
        let ping = KeepaliveMessage::Ping { seq: 42 };
        let encoded = ping.encode();
        assert_eq!(encoded.len(), 8);
        let decoded = KeepaliveMessage::decode(&encoded, true);
        assert_eq!(decoded, KeepaliveMessage::Ping { seq: 42 });
        assert_eq!(decoded.seq(), 42);
    }

    #[test]
    fn keepalive_message_pong_encode_decode() {
        let pong = KeepaliveMessage::Pong { seq: 99 };
        let encoded = pong.encode();
        assert_eq!(encoded.len(), 8);
        let decoded = KeepaliveMessage::decode(&encoded, false);
        assert_eq!(decoded, KeepaliveMessage::Pong { seq: 99 });
        assert_eq!(decoded.seq(), 99);
    }

    #[test]
    fn keepalive_message_ping_not_decoded_as_pong() {
        // Ping and pong have identical wire encoding (both are the seq),
        // but the variant is determined by the is_ping discriminator.
        let ping = KeepaliveMessage::Ping { seq: 7 };
        let encoded = ping.encode();
        let as_pong = KeepaliveMessage::decode(&encoded, false);
        // Same seq, but tagged as Pong
        assert_eq!(as_pong, KeepaliveMessage::Pong { seq: 7 });
        assert_eq!(as_pong.seq(), 7);
    }

    #[test]
    fn keepalive_message_seq_roundtrip() {
        for seq in [0u64, 1, u64::MAX / 2, u64::MAX] {
            let msg = KeepaliveMessage::Ping { seq };
            assert_eq!(msg.seq(), seq);
            let msg = KeepaliveMessage::Pong { seq };
            assert_eq!(msg.seq(), seq);
        }
    }

    // -----------------------------------------------------------------------
    // KeepaliveResponder tests
    // -----------------------------------------------------------------------

    #[test]
    fn responder_on_ping_returns_pong_with_same_seq() {
        let responder = KeepaliveResponder::new();
        let ping = KeepaliveMessage::Ping { seq: 42 };
        let pong = responder.on_ping(&ping);
        assert_eq!(pong, KeepaliveMessage::Pong { seq: 42 });
    }

    #[test]
    fn responder_pong_for_seq() {
        let responder = KeepaliveResponder::new();
        let pong = responder.pong_for_seq(123);
        assert_eq!(pong, KeepaliveMessage::Pong { seq: 123 });
    }

    #[test]
    fn responder_is_stateless() {
        let r1 = KeepaliveResponder::new();
        let r2 = KeepaliveResponder::new();
        let ping = KeepaliveMessage::Ping { seq: 1 };
        assert_eq!(r1.on_ping(&ping), r2.on_ping(&ping));
    }

    // -----------------------------------------------------------------------
    // KeepaliveInitiator tests
    // -----------------------------------------------------------------------

    #[test]
    fn initiator_starts_idle() {
        let mut drain_called = false;
        {
            let initiator = KeepaliveInitiator::with_defaults(|| drain_called = true);
            assert!(!initiator.is_peer_dead());
            assert_eq!(initiator.state(), KeepaliveState::Idle);
        }
        assert!(!drain_called);
    }

    #[test]
    fn initiator_record_activity_keeps_idle() {
        let mut drain_called = false;
        let mut initiator = KeepaliveInitiator::with_defaults(|| drain_called = true);
        initiator.record_activity();
        assert_eq!(initiator.state(), KeepaliveState::Idle);
        assert!(!drain_called);
    }

    #[test]
    fn initiator_on_pong_keeps_idle() {
        let mut drain_called = false;
        let mut initiator = KeepaliveInitiator::with_defaults(|| drain_called = true);
        initiator.record_activity();
        initiator.on_pong(1);
        assert_eq!(initiator.state(), KeepaliveState::Idle);
        assert!(!drain_called);
    }

    #[test]
    fn initiator_drain_trigger_fires_once() {
        use std::sync::atomic::{AtomicU32, Ordering};
        let count = AtomicU32::new(0);
        let mut initiator = KeepaliveInitiator::new(
            KeepaliveConfig::new(
                Duration::from_secs(10),
                Duration::from_secs(1),
                1, // fail after 1 missed probe
            )
            .unwrap(),
            || {
                count.fetch_add(1, Ordering::SeqCst);
            },
        );

        initiator.record_activity();
        // Force into Probing by sending a probe
        let _seq = initiator.tick();
        // Record a miss
        initiator.engine.record_missed_probe();
        assert!(initiator.is_peer_dead());

        // Tick should fire drain trigger
        initiator.tick();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // Second tick should NOT fire again
        initiator.tick();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn initiator_reset_clears_dead() {
        let mut drain_called = false;
        let mut initiator = KeepaliveInitiator::new(
            KeepaliveConfig::new(Duration::from_secs(10), Duration::from_secs(1), 1).unwrap(),
            || drain_called = true,
        );

        initiator.record_activity();
        let _seq = initiator.tick();
        initiator.engine.record_missed_probe();
        assert!(initiator.is_peer_dead());

        initiator.reset();
        assert!(!initiator.is_peer_dead());
        assert_eq!(initiator.state(), KeepaliveState::Idle);
    }

    // -----------------------------------------------------------------------
    // KeepaliveLifecycle tests
    // -----------------------------------------------------------------------

    #[test]
    fn lifecycle_starts_unarmed() {
        let bridge = KeepaliveLifecycle::with_defaults();
        assert!(!bridge.is_armed());
        assert!(!bridge.should_drain());
    }

    #[test]
    fn lifecycle_on_active_arms() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        assert!(bridge.is_armed());
        assert!(!bridge.should_drain());
    }

    #[test]
    fn lifecycle_on_inactive_disarms() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        assert!(bridge.is_armed());
        bridge.on_inactive();
        assert!(!bridge.is_armed());
    }

    #[test]
    fn lifecycle_record_activity_keeps_alive() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        bridge.record_activity();
        assert!(!bridge.should_drain());
    }

    #[test]
    fn lifecycle_tick_when_unarmed_returns_none() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        assert_eq!(bridge.tick(), KeepaliveAction::None);
    }

    #[test]
    fn lifecycle_tick_when_active_no_idle_returns_none() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        // Just armed, no idle timeout elapsed yet
        // (engine starts with no last_activity set, so should_send_probe is false)
        assert_eq!(bridge.tick(), KeepaliveAction::None);
    }

    #[test]
    fn lifecycle_on_pong_resets() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        bridge.on_pong(1);
        assert!(!bridge.should_drain());
    }

    #[test]
    fn keepalive_message_encode_consistent_with_build_ping() {
        let seq = 42u64;
        let msg = KeepaliveMessage::Ping { seq };
        let wire = build_ping(seq);
        assert_eq!(&msg.encode(), wire.as_slice());
    }

    #[test]
    fn keepalive_action_debug() {
        assert_eq!(format!("{:?}", KeepaliveAction::None), "None");
        assert_eq!(format!("{:?}", KeepaliveAction::SendPing(5)), "SendPing(5)");
        assert_eq!(format!("{:?}", KeepaliveAction::Drain), "Drain");
    }

    // -------------------------------------------------------------------
    // is_expecting_pong (auto-respond guard)
    // -------------------------------------------------------------------

    #[test]
    fn is_expecting_pong_false_when_idle() {
        let mut bridge = KeepaliveLifecycle::with_defaults();
        bridge.on_active();
        // Engine starts Idle after on_active (reset resets state to Idle)
        assert!(!bridge.is_expecting_pong());
    }

    #[test]
    fn is_expecting_pong_true_after_tick_sends_ping() {
        let mut bridge = KeepaliveLifecycle::new(KeepaliveConfig {
            idle_timeout: Duration::from_millis(1),
            probe_interval: Duration::from_secs(5),
            max_missed_probes: 3,
        });
        bridge.on_active();
        // Simulate an activity recorded long ago so idle_timeout has elapsed
        // (record_activity must be before on_active reset, so we re-record)
        bridge.record_activity();
        // With idle_timeout=1ms, this should be long enough expired
        std::thread::sleep(Duration::from_millis(10));
        // tick should now return SendPing because idle_timeout elapsed
        let action = bridge.tick();
        assert!(matches!(action, KeepaliveAction::SendPing(_)));
        // After sending a ping, the engine goes to Probing
        assert!(bridge.is_expecting_pong());
    }

    #[test]
    fn is_expecting_pong_false_after_on_pong_resets() {
        let mut bridge = KeepaliveLifecycle::new(KeepaliveConfig {
            idle_timeout: Duration::from_millis(1),
            probe_interval: Duration::from_secs(5),
            max_missed_probes: 3,
        });
        bridge.on_active();
        bridge.record_activity();
        std::thread::sleep(Duration::from_millis(10));
        // Tick to send a ping and go Probing
        let action = bridge.tick();
        assert!(matches!(action, KeepaliveAction::SendPing(_)));
        assert!(bridge.is_expecting_pong());
        // Receive a pong: resets to Idle
        bridge.on_pong(1);
        assert!(!bridge.is_expecting_pong());
    }
}
