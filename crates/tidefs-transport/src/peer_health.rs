// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Per-peer-connection health score aggregation with multi-signal weighting.
//!
//! This module fuses keepalive round-trip latency, error-classification event
//! rate, channel backpressure depth, and queue drain velocity into a single
//! weighted health score in [0.0, 1.0]. The score drives smarter
//! connection-lifecycle decisions and provides a richer signal to the
//! membership heartbeat protocol than binary alive/dead detection alone.
//!
//! ## Architecture
//!
//! ```text
//! keepalive RTT ──┐
//! error rate    ──┤
//! backpressure  ──┼──▶ PeerHealthAggregator ──▶ HealthTier ──▶ ConnectionHealthEvent
//! drain velocity──┤
//! connection uptime─┘
//! ```
//!
//! Each signal is tracked via an independent exponential moving average (EMA)
//! with a configurable decay half-life. The per-signal EMAs are combined into
//! an aggregate score through a weighted sum.
//!
//! ## Health tiers
//!
//! | Tier       | Range       | Meaning |
//! |------------|-------------|---------|
//! | Healthy    | [0.7, 1.0]  | Normal operation; membership heartbeat interval nominal |
//! | Degraded   | [0.3, 0.7)  | Stressed but usable; membership heartbeat interval halved |
//! | Unhealthy  | [0.0, 0.3)  | Connection should be drained or replaced |
//!
//! Tier thresholds are configurable via [`HealthScoreConfig`].
//!
//! ## Integration points
//!
//! - **keepalive**: emits `HealthSignal::KeepaliveRtt` on each probe response.
//! - **error_classification**: emits `HealthSignal::ErrorRate` on
//!   classification events.
//! - **send_dispatch**: emits `HealthSignal::BackpressureDepth` on queue
//!   depth changes.
//! - **receive_loop**: emits `HealthSignal::DrainVelocity` on batch drain
//!   completion.
//! - **connection state machine** (#5869): reacts to
//!   `ConnectionHealthEvent::TierTransition` emitted when `HealthTier`
//!   changes and the new tier is sustained for `sustain_duration`.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use crate::connection_registry::ConnectionId;

// ---------------------------------------------------------------------------
// HealthSignal
// ---------------------------------------------------------------------------

/// A discrete health signal ingested by the aggregator.
///
/// Each variant carries the raw measurement value. The aggregator normalizes
/// each signal into a [0.0, 1.0] contribution before blending.
#[derive(Clone, Copy, Debug)]
pub enum HealthSignal {
    /// Keepalive round-trip latency. Lower is better.
    KeepaliveRtt(Duration),
    /// Error classification event rate (errors per second). Lower is better.
    ErrorRate(f64),
    /// Current outbound queue depth (number of buffered messages). Lower is
    /// better.
    BackpressureDepth(usize),
    /// Receive drain velocity (messages per second). Higher is better.
    DrainVelocity(f64),
    /// Duration since connection establishment. Biases against flapping new
    /// connections.
    ConnectionUptime(Duration),
}

// ---------------------------------------------------------------------------
// HealthSignalSink
// ---------------------------------------------------------------------------

/// A sink that accepts health signals for a connection.
///
/// Implemented by [`HealthScoreRegistry`] so that signal-producing modules
/// (keepalive, error classification, send dispatch, receive loop) can feed
/// signals without depending on the registry implementation directly.
pub trait HealthSignalSink {
    /// Ingest a health signal for the given connection.
    ///
    /// Returns the updated aggregate score, or `None` if the connection
    /// is not tracked.
    fn ingest_signal(&mut self, conn_id: ConnectionId, signal: HealthSignal) -> Option<f64>;
}
// ---------------------------------------------------------------------------
// LivenessSignal -- bridge to membership-live peer liveness
// ---------------------------------------------------------------------------

/// A source of health scores for membership-live peer liveness decisions.
///
/// Implemented by [`PeerHealthAggregator`] so that the membership layer can
/// drive per-peer state transitions (Unknown -> Alive -> Suspect -> Dead) from
/// transport health validation without depending on the aggregator type directly.
pub trait LivenessSignal {
    /// Current health score in [0.0, 1.0], where 1.0 is optimal.
    fn health_score(&self) -> f64;
}

impl LivenessSignal for PeerHealthAggregator {
    fn health_score(&self) -> f64 {
        self.current_score()
    }
}

// ---------------------------------------------------------------------------
// SignalWeight
// ---------------------------------------------------------------------------

/// Per-signal weight and decay configuration.
///
/// Each signal contributes `weight * signal_ema` to the aggregate score.
/// Weights must be in [0.0, 1.0] and should sum to ≤1.0 across all signals.
/// The decay half-life controls how quickly old measurements lose influence.
#[derive(Clone, Copy, Debug)]
pub struct SignalWeight {
    /// Contribution weight of this signal (0.0–1.0).
    pub weight: f64,
    /// Decay half-life for the EMA. After `half_life` has elapsed, a
    /// measurement retains half its weight.
    pub half_life: Duration,
}

impl SignalWeight {
    /// Create a new signal weight, clamping `weight` to [0.0, 1.0].
    #[must_use]
    pub fn new(weight: f64, half_life: Duration) -> Self {
        Self {
            weight: weight.clamp(0.0, 1.0),
            half_life,
        }
    }

    /// Compute the EMA smoothing factor α for an elapsed duration.
    /// α = 1 - 2^(-Δt / half_life)
    #[must_use]
    pub fn alpha_for_elapsed(&self, elapsed: Duration) -> f64 {
        if self.half_life.is_zero() {
            return 1.0;
        }
        let ratio = elapsed.as_secs_f64() / self.half_life.as_secs_f64();
        1.0 - 2.0_f64.powf(-ratio)
    }
}

// ---------------------------------------------------------------------------
// HealthTier
// ---------------------------------------------------------------------------

/// Discrete health tier derived from the aggregate score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HealthTier {
    /// Connection is unhealthy: score < `unhealthy_threshold`.
    Unhealthy,
    /// Connection is degraded: `unhealthy_threshold` ≤ score <
    /// `healthy_threshold`.
    Degraded,
    /// Connection is healthy: score ≥ `healthy_threshold`.
    Healthy,
}

impl fmt::Display for HealthTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Degraded => write!(f, "Degraded"),
            Self::Unhealthy => write!(f, "Unhealthy"),
        }
    }
}

// ---------------------------------------------------------------------------
// HealthScoreConfig
// ---------------------------------------------------------------------------

/// Builder-pattern configuration for the health score aggregator.
#[derive(Clone, Debug)]
pub struct HealthScoreConfig {
    /// Weight and decay for keepalive RTT signal.
    pub keepalive_rtt: SignalWeight,
    /// Weight and decay for error rate signal.
    pub error_rate: SignalWeight,
    /// Weight and decay for backpressure depth signal.
    pub backpressure_depth: SignalWeight,
    /// Weight and decay for drain velocity signal.
    pub drain_velocity: SignalWeight,
    /// Weight and decay for connection uptime signal.
    pub connection_uptime: SignalWeight,
    /// Score threshold above which a connection is Healthy.
    pub healthy_threshold: f64,
    /// Score threshold below which a connection is Unhealthy.
    pub unhealthy_threshold: f64,
    /// Duration a new tier must be sustained before
    /// [`ConnectionHealthEvent::TierTransition`] is emitted.
    pub sustain_duration: Duration,
}

impl Default for HealthScoreConfig {
    fn default() -> Self {
        Self {
            keepalive_rtt: SignalWeight::new(0.30, Duration::from_secs(30)),
            error_rate: SignalWeight::new(0.25, Duration::from_secs(60)),
            backpressure_depth: SignalWeight::new(0.20, Duration::from_secs(15)),
            drain_velocity: SignalWeight::new(0.15, Duration::from_secs(30)),
            connection_uptime: SignalWeight::new(0.10, Duration::from_secs(300)),
            healthy_threshold: 0.7,
            unhealthy_threshold: 0.3,
            sustain_duration: Duration::from_secs(5),
        }
    }
}

impl HealthScoreConfig {
    /// Create a new config with builder defaults.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set keepalive RTT weight and half-life.
    #[must_use]
    pub fn with_keepalive_rtt(mut self, weight: f64, half_life: Duration) -> Self {
        self.keepalive_rtt = SignalWeight::new(weight, half_life);
        self
    }

    /// Set error rate weight and half-life.
    #[must_use]
    pub fn with_error_rate(mut self, weight: f64, half_life: Duration) -> Self {
        self.error_rate = SignalWeight::new(weight, half_life);
        self
    }

    /// Set backpressure depth weight and half-life.
    #[must_use]
    pub fn with_backpressure_depth(mut self, weight: f64, half_life: Duration) -> Self {
        self.backpressure_depth = SignalWeight::new(weight, half_life);
        self
    }

    /// Set drain velocity weight and half-life.
    #[must_use]
    pub fn with_drain_velocity(mut self, weight: f64, half_life: Duration) -> Self {
        self.drain_velocity = SignalWeight::new(weight, half_life);
        self
    }

    /// Set connection uptime weight and half-life.
    #[must_use]
    pub fn with_connection_uptime(mut self, weight: f64, half_life: Duration) -> Self {
        self.connection_uptime = SignalWeight::new(weight, half_life);
        self
    }

    /// Set the healthy and unhealthy score thresholds.
    #[must_use]
    pub fn with_thresholds(mut self, healthy: f64, unhealthy: f64) -> Self {
        self.healthy_threshold = healthy.clamp(0.0, 1.0);
        self.unhealthy_threshold = unhealthy.clamp(0.0, 1.0);
        self
    }

    /// Set the tier-transition sustain duration.
    #[must_use]
    pub fn with_sustain_duration(mut self, d: Duration) -> Self {
        self.sustain_duration = d;
        self
    }

    /// Validate that thresholds are consistent
    /// (0 ≤ unhealthy < healthy ≤ 1).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.unhealthy_threshold < 0.0 || self.unhealthy_threshold > 1.0 {
            return Err("unhealthy_threshold must be in [0.0, 1.0]");
        }
        if self.healthy_threshold < 0.0 || self.healthy_threshold > 1.0 {
            return Err("healthy_threshold must be in [0.0, 1.0]");
        }
        if self.unhealthy_threshold >= self.healthy_threshold {
            return Err("unhealthy_threshold must be < healthy_threshold");
        }
        Ok(())
    }

    /// Sum of all signal weights (informational).
    #[must_use]
    pub fn total_weight(&self) -> f64 {
        self.keepalive_rtt.weight
            + self.error_rate.weight
            + self.backpressure_depth.weight
            + self.drain_velocity.weight
            + self.connection_uptime.weight
    }
}

// ---------------------------------------------------------------------------
// Per-signal EMA state
// ---------------------------------------------------------------------------

/// Internal exponential-moving-average state for a single signal.
#[derive(Clone, Debug)]
struct SignalEma {
    /// Current EMA value in [0.0, 1.0].
    value: f64,
    /// When the last update occurred.
    last_update: Instant,
    /// Whether this signal has received any data yet.
    initialized: bool,
}

impl SignalEma {
    fn new() -> Self {
        Self {
            value: 0.5, // neutral starting point
            last_update: Instant::now(),
            initialized: false,
        }
    }

    /// Apply a new raw measurement and return the updated EMA value.
    fn update(&mut self, raw: f64, weight: &SignalWeight) -> f64 {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update);
        let alpha = weight.alpha_for_elapsed(elapsed);

        if !self.initialized {
            self.value = raw;
            self.initialized = true;
        } else {
            self.value = alpha.mul_add(raw - self.value, self.value);
        }
        self.value = self.value.clamp(0.0, 1.0);
        self.last_update = now;
        self.value
    }

    fn current(&self) -> f64 {
        self.value
    }
}

// ---------------------------------------------------------------------------
// PeerHealthAggregator
// ---------------------------------------------------------------------------

/// Per-connection aggregator that accepts [`HealthSignal`] events, maintains
/// per-signal EMA state, and computes the weighted aggregate score and
/// corresponding [`HealthTier`].
#[derive(Clone, Debug)]
pub struct PeerHealthAggregator {
    config: HealthScoreConfig,
    keepalive_ema: SignalEma,
    error_rate_ema: SignalEma,
    backpressure_ema: SignalEma,
    drain_velocity_ema: SignalEma,
    uptime_ema: SignalEma,
    connection_start: Instant,
    current_tier: HealthTier,
    tier_since: Instant,
    /// The first time the *pending* tier was observed (different from current_tier).
    pending_tier: Option<(HealthTier, Instant)>,
}

impl PeerHealthAggregator {
    /// Create a new aggregator with the given config.
    #[must_use]
    pub fn new(config: HealthScoreConfig) -> Self {
        let now = Instant::now();
        Self {
            config,
            keepalive_ema: SignalEma::new(),
            error_rate_ema: SignalEma::new(),
            backpressure_ema: SignalEma::new(),
            drain_velocity_ema: SignalEma::new(),
            uptime_ema: SignalEma::new(),
            connection_start: now,
            current_tier: HealthTier::Healthy,
            tier_since: now,
            pending_tier: None,
        }
    }

    /// Ingest a health signal and update the corresponding EMA.
    ///
    /// Returns the new aggregate score if any EMAs changed, or `None` if
    /// the signal was a no-op (e.g. an already-seen uptime reading).
    pub fn ingest(&mut self, signal: HealthSignal) -> Option<f64> {
        let raw = self.normalize(signal);
        match signal {
            HealthSignal::KeepaliveRtt(_) => {
                self.keepalive_ema.update(raw, &self.config.keepalive_rtt);
            }
            HealthSignal::ErrorRate(_) => {
                self.error_rate_ema.update(raw, &self.config.error_rate);
            }
            HealthSignal::BackpressureDepth(_) => {
                self.backpressure_ema
                    .update(raw, &self.config.backpressure_depth);
            }
            HealthSignal::DrainVelocity(_) => {
                self.drain_velocity_ema
                    .update(raw, &self.config.drain_velocity);
            }
            HealthSignal::ConnectionUptime(_) => {
                self.uptime_ema.update(raw, &self.config.connection_uptime);
            }
        }
        Some(self.compute_score())
    }

    /// Compute the current weighted aggregate score.
    #[must_use]
    pub fn current_score(&self) -> f64 {
        self.compute_score()
    }

    /// Return the current health tier.
    #[must_use]
    pub fn health_tier(&self) -> HealthTier {
        self.current_tier
    }

    /// Return the duration since this aggregator was created
    /// (connection uptime).
    #[must_use]
    pub fn connection_uptime(&self) -> Duration {
        self.connection_start.elapsed()
    }

    /// Check whether the tier has transitioned (with sustain check) and
    /// advance the state machine. Returns a [`ConnectionHealthEvent`] if
    /// a tier transition just completed.
    pub fn poll_tier_transition(&mut self) -> Option<ConnectionHealthEvent> {
        let score = self.compute_score();
        let raw_tier = self.classify(score);

        if raw_tier == self.current_tier {
            // Reset pending if the tier reverted
            self.pending_tier = None;
            return None;
        }

        let now = Instant::now();
        match self.pending_tier {
            Some((pending, since)) if pending == raw_tier => {
                if now.duration_since(since) >= self.config.sustain_duration {
                    let old = self.current_tier;
                    self.current_tier = raw_tier;
                    self.tier_since = now;
                    self.pending_tier = None;
                    return Some(ConnectionHealthEvent::TierTransition {
                        conn_id: None, // filled by registry
                        old_tier: old,
                        new_tier: raw_tier,
                        score,
                    });
                }
            }
            _ => {
                self.pending_tier = Some((raw_tier, now));
            }
        }
        None
    }

    // -- private helpers --

    fn compute_score(&self) -> f64 {
        let cfg = &self.config;
        let raw = cfg.keepalive_rtt.weight * self.keepalive_ema.current()
            + cfg.error_rate.weight * self.error_rate_ema.current()
            + cfg.backpressure_depth.weight * self.backpressure_ema.current()
            + cfg.drain_velocity.weight * self.drain_velocity_ema.current()
            + cfg.connection_uptime.weight * self.uptime_ema.current();

        raw.clamp(0.0, 1.0)
    }

    fn classify(&self, score: f64) -> HealthTier {
        if score >= self.config.healthy_threshold {
            HealthTier::Healthy
        } else if score >= self.config.unhealthy_threshold {
            HealthTier::Degraded
        } else {
            HealthTier::Unhealthy
        }
    }

    /// Normalize a raw signal into [0.0, 1.0] where 1.0 is optimal.
    fn normalize(&self, signal: HealthSignal) -> f64 {
        match signal {
            HealthSignal::KeepaliveRtt(rtt) => {
                // RTT < 1ms => 1.0, RTT > 500ms => 0.0
                let ms = rtt.as_secs_f64() * 1000.0;
                if ms <= 1.0 {
                    1.0
                } else if ms >= 500.0 {
                    0.0
                } else {
                    1.0 - ((ms - 1.0) / 499.0)
                }
            }
            HealthSignal::ErrorRate(rate) => {
                // 0 errors/s => 1.0, >= 10 errors/s => 0.0
                if rate <= 0.0 {
                    1.0
                } else if rate >= 10.0 {
                    0.0
                } else {
                    1.0 - rate / 10.0
                }
            }
            HealthSignal::BackpressureDepth(depth) => {
                // 0 queue depth => 1.0, >= 1000 => 0.0
                let d = depth as f64;
                if d <= 0.0 {
                    1.0
                } else if d >= 1000.0 {
                    0.0
                } else {
                    1.0 - d / 1000.0
                }
            }
            HealthSignal::DrainVelocity(v) => {
                // >= 10000 msg/s => 1.0, 0 => 0.0
                if v >= 10000.0 {
                    1.0
                } else if v <= 0.0 {
                    0.0
                } else {
                    v / 10000.0
                }
            }
            HealthSignal::ConnectionUptime(uptime) => {
                // >= 60s => 1.0, 0 => 0.0
                let secs = uptime.as_secs_f64();
                if secs >= 60.0 {
                    1.0
                } else {
                    secs / 60.0
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// ConnectionHealthEvent
// ---------------------------------------------------------------------------

/// An event emitted by [`HealthScoreRegistry`] when a connection's health
/// tier transitions after the sustain duration.
#[derive(Clone, Debug)]
pub enum ConnectionHealthEvent {
    /// A connection's health tier has changed and the new tier has been
    /// sustained for the configured duration.
    TierTransition {
        /// The connection that changed (set by the registry).
        conn_id: Option<ConnectionId>,
        /// The previous tier.
        old_tier: HealthTier,
        /// The new tier.
        new_tier: HealthTier,
        /// The aggregate score at the time of transition.
        score: f64,
    },
}

// ---------------------------------------------------------------------------
// HealthScoreRegistry
// ---------------------------------------------------------------------------

/// Registry mapping connection IDs to [`PeerHealthAggregator`] instances.
///
/// Provides `ingest(conn_id, signal)` and `get(conn_id)` methods for
/// integration with signal-producing modules (keepalive, error
/// classification, send dispatch, receive loop).
#[derive(Clone, Debug)]
pub struct HealthScoreRegistry {
    entries: HashMap<ConnectionId, PeerHealthAggregator>,
    config: HealthScoreConfig,
}

impl HealthScoreRegistry {
    /// Create a new registry with the given default config.
    #[must_use]
    pub fn new(config: HealthScoreConfig) -> Self {
        Self {
            entries: HashMap::new(),
            config,
        }
    }

    /// Register a new connection for health tracking.
    ///
    /// Returns `None` if the connection was already registered; otherwise
    /// returns the newly created aggregator reference.
    pub fn register(&mut self, conn_id: ConnectionId) -> Option<&PeerHealthAggregator> {
        if self.entries.contains_key(&conn_id) {
            return None;
        }
        let agg = PeerHealthAggregator::new(self.config.clone());
        self.entries.insert(conn_id, agg);
        self.entries.get(&conn_id)
    }

    /// Remove a connection from health tracking (e.g. on teardown).
    pub fn remove(&mut self, conn_id: ConnectionId) -> Option<PeerHealthAggregator> {
        self.entries.remove(&conn_id)
    }

    /// Ingest a health signal for a connection. Creates the aggregator
    /// if not already registered.
    ///
    /// Returns the new aggregate score, or `None` if the connection was
    /// not found and auto-registration is disabled.
    pub fn ingest(&mut self, conn_id: ConnectionId, signal: HealthSignal) -> Option<f64> {
        let agg = self
            .entries
            .entry(conn_id)
            .or_insert_with(|| PeerHealthAggregator::new(self.config.clone()));
        agg.ingest(signal)
    }

    /// Look up an aggregator by connection ID.
    #[must_use]
    pub fn get(&self, conn_id: ConnectionId) -> Option<&PeerHealthAggregator> {
        self.entries.get(&conn_id)
    }

    /// Look up an aggregator mutably by connection ID.
    #[must_use]
    pub fn get_mut(&mut self, conn_id: ConnectionId) -> Option<&mut PeerHealthAggregator> {
        self.entries.get_mut(&conn_id)
    }

    /// Poll all connections for tier transitions.
    ///
    /// Returns all [`ConnectionHealthEvent::TierTransition`] events that
    /// completed during this poll, with `conn_id` populated.
    pub fn poll_all(&mut self) -> Vec<ConnectionHealthEvent> {
        let mut events = Vec::new();
        for (&conn_id, agg) in &mut self.entries {
            if let Some(mut ev) = agg.poll_tier_transition() {
                let ConnectionHealthEvent::TierTransition {
                    conn_id: ref mut cid_field,
                    ..
                } = &mut ev;
                *cid_field = Some(conn_id);
                events.push(ev);
            }
        }
        events
    }

    /// Number of tracked connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl HealthSignalSink for HealthScoreRegistry {
    fn ingest_signal(&mut self, conn_id: ConnectionId, signal: HealthSignal) -> Option<f64> {
        self.ingest(conn_id, signal)
    }
}

// ---------------------------------------------------------------------------
// SharedHealthScoreRegistry
// ---------------------------------------------------------------------------

/// Thread-safe shared reference to a [`HealthScoreRegistry`].
///
/// Used to share the registry across signal-producing modules (keepalive,
/// error classification, send dispatch, receive loop) and the connection
/// lifecycle subscriber.
pub type SharedHealthScoreRegistry = std::sync::Arc<std::sync::Mutex<HealthScoreRegistry>>;

/// Create a new shared registry with the given config.
#[must_use]
pub fn new_shared_registry(config: HealthScoreConfig) -> SharedHealthScoreRegistry {
    std::sync::Arc::new(std::sync::Mutex::new(HealthScoreRegistry::new(config)))
}

// ---------------------------------------------------------------------------
// PeerHealthLifecycleSubscriber
// ---------------------------------------------------------------------------

/// A [`LifecycleSubscriber`](crate::connection_state::LifecycleSubscriber)
/// that wires [`HealthScoreRegistry`] lifecycle into the connection state
/// machine.
///
/// - On `Active`: registers the connection for health tracking.
/// - On `Closed` / `DrainComplete`: removes the connection.
///
/// The subscriber holds the connection ID and a shared reference to the
/// registry. Instantiate one per connection and subscribe it to the
/// connection's [`LifecycleBus`](crate::connection_state::LifecycleBus).
#[derive(Clone, Debug)]
pub struct PeerHealthLifecycleSubscriber {
    conn_id: ConnectionId,
    registry: SharedHealthScoreRegistry,
}

impl PeerHealthLifecycleSubscriber {
    /// Create a new subscriber for the given connection and shared registry.
    #[must_use]
    pub fn new(conn_id: ConnectionId, registry: SharedHealthScoreRegistry) -> Self {
        Self { conn_id, registry }
    }
}

impl crate::connection_state::LifecycleSubscriber for PeerHealthLifecycleSubscriber {
    fn on_lifecycle_event(&self, event: &crate::connection_state::LifecycleEvent) {
        match event {
            crate::connection_state::LifecycleEvent::Active { .. } => {
                let mut reg = self.registry.lock().unwrap();
                reg.register(self.conn_id);
            }
            crate::connection_state::LifecycleEvent::Closed { .. }
            | crate::connection_state::LifecycleEvent::DrainComplete { .. } => {
                let mut reg = self.registry.lock().unwrap();
                reg.remove(self.conn_id);
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- SignalWeight tests --

    #[test]
    fn signal_weight_alpha_zero_elapsed() {
        let w = SignalWeight::new(0.5, Duration::from_secs(10));
        let alpha = w.alpha_for_elapsed(Duration::ZERO);
        assert!((alpha - 0.0).abs() < 1e-9);
    }

    #[test]
    fn signal_weight_alpha_at_half_life() {
        let w = SignalWeight::new(0.5, Duration::from_secs(10));
        let alpha = w.alpha_for_elapsed(Duration::from_secs(10));
        assert!((alpha - 0.5).abs() < 1e-9);
    }

    #[test]
    fn signal_weight_alpha_zero_half_life() {
        let w = SignalWeight::new(0.5, Duration::ZERO);
        let alpha = w.alpha_for_elapsed(Duration::from_secs(1));
        assert!((alpha - 1.0).abs() < 1e-9);
    }

    #[test]
    fn signal_weight_clamps_to_range() {
        let w = SignalWeight::new(1.5, Duration::from_secs(1));
        assert!((w.weight - 1.0).abs() < 1e-9);
        let w = SignalWeight::new(-0.3, Duration::from_secs(1));
        assert!((w.weight - 0.0).abs() < 1e-9);
    }

    // -- HealthScoreConfig tests --

    #[test]
    fn config_defaults_sane() {
        let cfg = HealthScoreConfig::default();
        assert!(cfg.validate().is_ok());
        assert!(cfg.healthy_threshold > cfg.unhealthy_threshold);
        assert!((cfg.total_weight() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn config_validate_rejects_bad_thresholds() {
        let cfg = HealthScoreConfig::default().with_thresholds(0.5, 0.8);
        assert!(cfg.validate().is_err());

        let cfg = HealthScoreConfig::default().with_thresholds(0.5, 0.5);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_builder_methods() {
        let cfg = HealthScoreConfig::new()
            .with_keepalive_rtt(0.4, Duration::from_secs(20))
            .with_error_rate(0.3, Duration::from_secs(40))
            .with_backpressure_depth(0.2, Duration::from_secs(10))
            .with_drain_velocity(0.05, Duration::from_secs(60))
            .with_connection_uptime(0.05, Duration::from_secs(120))
            .with_thresholds(0.75, 0.25)
            .with_sustain_duration(Duration::from_secs(3));

        assert!((cfg.keepalive_rtt.weight - 0.4).abs() < 1e-9);
        assert!((cfg.error_rate.weight - 0.3).abs() < 1e-9);
        assert!((cfg.healthy_threshold - 0.75).abs() < 1e-9);
        assert!((cfg.unhealthy_threshold - 0.25).abs() < 1e-9);
        assert_eq!(cfg.sustain_duration, Duration::from_secs(3));
        assert!(cfg.validate().is_ok());
    }

    // -- PeerHealthAggregator tests --

    #[test]
    fn aggregator_initial_healthy() {
        let agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        assert_eq!(agg.health_tier(), HealthTier::Healthy);
    }

    #[test]
    fn aggregator_rtt_normalization() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        // 1ms RTT => score ~1.0 for that signal
        agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(1)));
        let score = agg.current_score();
        assert!(
            score > 0.6,
            "score should be high with good RTT, got {score}"
        );

        // 500ms RTT => should degrade
        agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(500)));
        let score2 = agg.current_score();
        assert!(score2 < score, "score should drop with bad RTT");
    }

    #[test]
    fn aggregator_error_rate_normalization() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        // Zero errors => high
        agg.ingest(HealthSignal::ErrorRate(0.0));
        let score = agg.current_score();
        // Uninitialized signals default to 0.5. Weighted max:
        // 0.25*1.0 (error_rate) + 0.75*0.5 (rest) = 0.625
        assert!(
            score > 0.6,
            "score should be high with zero errors, got {score}"
        );

        // 10 errors/s => low
        agg.ingest(HealthSignal::ErrorRate(10.0));
        let score2 = agg.current_score();
        assert!(score2 < score, "score should drop with high error rate");
    }

    #[test]
    fn aggregator_backpressure_normalization() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        agg.ingest(HealthSignal::BackpressureDepth(0));
        let score = agg.current_score();
        assert!(score > 0.6);

        agg.ingest(HealthSignal::BackpressureDepth(1000));
        let score2 = agg.current_score();
        assert!(
            score2 <= score,
            "score should not increase with full backpressure"
        );
    }

    #[test]
    fn aggregator_drain_velocity_normalization() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        agg.ingest(HealthSignal::DrainVelocity(10000.0));
        let score = agg.current_score();
        // DrainVelocity weight 0.15: 0.15*1.0 + 0.85*0.5 = 0.575
        assert!(score >= 0.55);

        agg.ingest(HealthSignal::DrainVelocity(0.0));
        let score2 = agg.current_score();
        assert!(
            score2 <= score,
            "score should not increase with full backpressure"
        );
    }

    #[test]
    fn aggregator_uptime_normalization() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        agg.ingest(HealthSignal::ConnectionUptime(Duration::from_secs(60)));
        let score = agg.current_score();
        // Uptime weight 0.10: 0.10*1.0 + 0.90*0.5 = 0.55
        assert!(score >= 0.55);

        agg.ingest(HealthSignal::ConnectionUptime(Duration::from_secs(0)));
        let score2 = agg.current_score();
        assert!(
            score2 <= score,
            "score should not increase with full backpressure"
        );
    }

    #[test]
    fn aggregator_multi_signal_composite() {
        let cfg = HealthScoreConfig::default();
        // Good signals: fresh aggregator, all optimal inputs
        let mut good_agg = PeerHealthAggregator::new(cfg.clone());
        good_agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(1)));
        good_agg.ingest(HealthSignal::ErrorRate(0.0));
        good_agg.ingest(HealthSignal::BackpressureDepth(0));
        good_agg.ingest(HealthSignal::DrainVelocity(10000.0));
        good_agg.ingest(HealthSignal::ConnectionUptime(Duration::from_secs(60)));
        let good_score = good_agg.current_score();
        assert!(
            good_score > 0.8,
            "all-good score should be high, got {good_score}"
        );

        // Bad signals: fresh aggregator, all worst-case inputs
        let mut bad_agg = PeerHealthAggregator::new(cfg);
        bad_agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(500)));
        bad_agg.ingest(HealthSignal::ErrorRate(10.0));
        bad_agg.ingest(HealthSignal::BackpressureDepth(1000));
        bad_agg.ingest(HealthSignal::DrainVelocity(0.0));
        bad_agg.ingest(HealthSignal::ConnectionUptime(Duration::ZERO));
        let bad_score = bad_agg.current_score();
        assert!(
            bad_score < 0.5,
            "all-bad score should be low, got {bad_score}"
        );
        assert!(
            good_score > bad_score,
            "good {good_score} should exceed bad {bad_score}"
        );
    }

    #[test]
    fn aggregator_tier_classification_boundaries() {
        let cfg = HealthScoreConfig::default().with_thresholds(0.7, 0.3);
        let agg = PeerHealthAggregator::new(cfg);

        assert_eq!(agg.classify(1.0), HealthTier::Healthy);
        assert_eq!(agg.classify(0.7), HealthTier::Healthy);
        assert_eq!(agg.classify(0.5), HealthTier::Degraded);
        assert_eq!(agg.classify(0.3), HealthTier::Degraded);
        assert_eq!(agg.classify(0.29), HealthTier::Unhealthy);
        assert_eq!(agg.classify(0.0), HealthTier::Unhealthy);
    }

    #[test]
    fn aggregator_tier_transition_sustain() {
        let cfg = HealthScoreConfig::default()
            .with_sustain_duration(Duration::from_millis(1))
            .with_thresholds(0.9, 0.3);
        let mut agg = PeerHealthAggregator::new(cfg.clone());

        // Start healthy
        assert_eq!(agg.health_tier(), HealthTier::Healthy);

        // Ingest terrible signal to push score low
        agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(500)));
        agg.ingest(HealthSignal::ErrorRate(10.0));
        agg.ingest(HealthSignal::BackpressureDepth(1000));
        agg.ingest(HealthSignal::DrainVelocity(0.0));

        // Poll - should not immediately transition (sustain duration hasn't passed)
        let event = agg.poll_tier_transition();
        assert!(event.is_none(), "should not transition before sustain");

        // Wait for sustain (1ms)
        std::thread::sleep(Duration::from_millis(2));

        let event = agg.poll_tier_transition();
        assert!(event.is_some(), "should transition after sustain");
        if let Some(ConnectionHealthEvent::TierTransition {
            old_tier, new_tier, ..
        }) = event
        {
            assert_eq!(old_tier, HealthTier::Healthy);
            assert_eq!(new_tier, HealthTier::Unhealthy);
        }
    }

    #[test]
    fn aggregator_pending_revert() {
        let cfg = HealthScoreConfig::default()
            .with_sustain_duration(Duration::from_secs(10))
            .with_thresholds(0.9, 0.3);
        let mut agg = PeerHealthAggregator::new(cfg);

        // Push to unhealthy briefly
        agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(500)));
        agg.ingest(HealthSignal::ErrorRate(10.0));
        agg.ingest(HealthSignal::BackpressureDepth(1000));
        agg.ingest(HealthSignal::DrainVelocity(0.0));

        // First poll: sees pending unhealthy
        let ev = agg.poll_tier_transition();
        assert!(ev.is_none());

        // Now push back to healthy (good signals)
        agg.ingest(HealthSignal::KeepaliveRtt(Duration::from_millis(1)));
        agg.ingest(HealthSignal::ErrorRate(0.0));
        agg.ingest(HealthSignal::BackpressureDepth(0));
        agg.ingest(HealthSignal::DrainVelocity(10000.0));

        // Now poll: pending should revert
        let ev = agg.poll_tier_transition();
        assert!(ev.is_none(), "pending tier reverted, no transition");
        assert_eq!(agg.health_tier(), HealthTier::Healthy);
    }

    // -- HealthScoreRegistry tests --

    #[test]
    fn registry_insert_lookup_remove() {
        let cfg = HealthScoreConfig::default();
        let mut reg = HealthScoreRegistry::new(cfg);
        let cid = ConnectionId::new(42);

        assert!(reg.register(cid).is_some());
        assert!(reg.get(cid).is_some());
        assert_eq!(reg.len(), 1);

        // Double register returns None
        assert!(reg.register(cid).is_none());

        // Remove
        let removed = reg.remove(cid);
        assert!(removed.is_some());
        assert!(reg.get(cid).is_none());
        assert!(reg.is_empty());
    }

    #[test]
    fn registry_ingest_auto_register() {
        let cfg = HealthScoreConfig::default();
        let mut reg = HealthScoreRegistry::new(cfg);
        let cid = ConnectionId::new(7);

        let score = reg.ingest(cid, HealthSignal::KeepaliveRtt(Duration::from_millis(1)));
        assert!(score.is_some());
        assert!(reg.get(cid).is_some());
    }

    #[test]
    fn registry_ingest_updates_score() {
        let cfg = HealthScoreConfig::default();
        let mut reg = HealthScoreRegistry::new(cfg);
        let cid = ConnectionId::new(1);

        let score1 = reg
            .ingest(cid, HealthSignal::KeepaliveRtt(Duration::from_millis(1)))
            .unwrap();
        let score2 = reg
            .ingest(cid, HealthSignal::KeepaliveRtt(Duration::from_millis(500)))
            .unwrap();
        assert!(score2 < score1, "score should degrade with bad RTT");
    }

    #[test]
    fn registry_poll_all_emits_events() {
        let cfg = HealthScoreConfig::default()
            .with_sustain_duration(Duration::from_millis(1))
            .with_thresholds(0.9, 0.3);
        let mut reg = HealthScoreRegistry::new(cfg);
        let cid = ConnectionId::new(1);

        // Auto-register via ingest
        reg.ingest(cid, HealthSignal::KeepaliveRtt(Duration::from_millis(500)));
        reg.ingest(cid, HealthSignal::ErrorRate(10.0));
        reg.ingest(cid, HealthSignal::BackpressureDepth(1000));
        reg.ingest(cid, HealthSignal::DrainVelocity(0.0));

        // First poll triggers pending_tier
        let events = reg.poll_all();
        assert!(events.is_empty(), "first poll should not transition");

        std::thread::sleep(Duration::from_millis(2));

        // Second poll after sustain should transition
        let events = reg.poll_all();
        assert_eq!(events.len(), 1);
        let ConnectionHealthEvent::TierTransition {
            conn_id,
            old_tier,
            new_tier,
            ..
        } = &events[0];
        assert_eq!(*conn_id, Some(cid));
        assert_eq!(*old_tier, HealthTier::Healthy);
        assert_eq!(*new_tier, HealthTier::Unhealthy);
    }

    #[test]
    fn health_tier_display() {
        assert_eq!(HealthTier::Healthy.to_string(), "Healthy");
        assert_eq!(HealthTier::Degraded.to_string(), "Degraded");
        assert_eq!(HealthTier::Unhealthy.to_string(), "Unhealthy");
    }

    #[test]
    fn health_tier_ordering() {
        assert!(HealthTier::Unhealthy < HealthTier::Degraded);
        assert!(HealthTier::Degraded < HealthTier::Healthy);
    }

    // -- Edge cases --

    #[test]
    fn empty_registry() {
        let cfg = HealthScoreConfig::default();
        let reg = HealthScoreRegistry::new(cfg);
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.get(ConnectionId::new(1)).is_none());
    }

    #[test]
    fn non_existent_connection_poll() {
        let cfg = HealthScoreConfig::default();
        let mut reg = HealthScoreRegistry::new(cfg);
        let events = reg.poll_all();
        assert!(events.is_empty());
    }

    #[test]
    fn aggregator_no_change_poll() {
        let mut agg = PeerHealthAggregator::new(HealthScoreConfig::default());
        // With default thresholds and good signals, stays healthy, no transition
        agg.ingest(HealthSignal::ConnectionUptime(Duration::from_secs(60)));
        let ev = agg.poll_tier_transition();
        assert!(ev.is_none());
    }
}
