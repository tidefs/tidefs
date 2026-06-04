//! Peer-connectivity health scoring engine.
//!
//! Consumes transport-derived per-peer metrics — round-trip latency, error
//! rate, message throughput, and keepalive miss count — and computes weighted
//! health scores driving peer status transitions between Healthy, Suspected,
//! and Unhealthy states. Status transitions are emitted through a broadcast
//! channel consumed by the eviction executor, reconnect handshake, and
//! placement planner.
//!
//! # State Transition Diagram
//!
//! ```text
//!                  score < suspect_threshold for suspect_grace_period
//!     HEALTHY  ------------------------------------------------> SUSPECTED
//!        ^                                                           |
//!        |              score < unhealthy_threshold                  |
//!        |              for unhealthy_grace_period                   |
//!        |                                                           v
//!        |                                                      UNHEALTHY
//!        |                                                           |
//!        +-----------------------------------------------------------+
//!              score > recovery_threshold for recovery_grace_period
//! ```
//!
//! Hysteresis prevents status flapping under oscillating metrics.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tidefs_membership_epoch::MemberId;
use tokio::sync::broadcast;

// ---------------------------------------------------------------------------
// ScorerConfig
// ---------------------------------------------------------------------------

/// Configuration for the peer-connectivity health scorer.
#[derive(Clone, Debug)]
pub struct ScorerConfig {
    pub weight_rtt: f64,
    pub weight_error_rate: f64,
    pub weight_throughput: f64,
    pub weight_keepalive: f64,
    pub half_life_samples: u64,
    pub rtt_half_us: f64,
    pub expected_throughput: f64,
    pub max_keepalive_misses: u32,
    pub min_samples_before_active: u64,
    pub suspect_threshold: f64,
    pub unhealthy_threshold: f64,
    pub recovery_threshold: f64,
    pub suspect_grace_period: Duration,
    pub unhealthy_grace_period: Duration,
    pub recovery_grace_period: Duration,
    pub broadcast_capacity: usize,
}

impl Default for ScorerConfig {
    fn default() -> Self {
        Self {
            weight_rtt: 0.30,
            weight_error_rate: 0.30,
            weight_throughput: 0.20,
            weight_keepalive: 0.20,
            half_life_samples: 8,
            rtt_half_us: 2000.0,
            expected_throughput: 10000.0,
            max_keepalive_misses: 5,
            min_samples_before_active: 4,
            suspect_threshold: 0.60,
            unhealthy_threshold: 0.30,
            recovery_threshold: 0.70,
            suspect_grace_period: Duration::from_secs(3),
            unhealthy_grace_period: Duration::from_secs(5),
            recovery_grace_period: Duration::from_secs(4),
            broadcast_capacity: 64,
        }
    }
}

impl ScorerConfig {
    pub fn builder() -> ScorerConfigBuilder {
        ScorerConfigBuilder::new()
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.suspect_threshold <= self.unhealthy_threshold {
            return Err(format!(
                "suspect_threshold ({}) must be > unhealthy_threshold ({})",
                self.suspect_threshold, self.unhealthy_threshold
            ));
        }
        if self.recovery_threshold <= self.suspect_threshold {
            return Err(format!(
                "recovery_threshold ({}) must be > suspect_threshold ({})",
                self.recovery_threshold, self.suspect_threshold
            ));
        }
        if self.suspect_threshold >= 1.0 || self.suspect_threshold <= 0.0 {
            return Err("suspect_threshold must be in (0.0, 1.0)".to_string());
        }
        if self.unhealthy_threshold >= 1.0 || self.unhealthy_threshold <= 0.0 {
            return Err("unhealthy_threshold must be in (0.0, 1.0)".to_string());
        }
        if self.recovery_threshold > 1.0 {
            return Err("recovery_threshold must be <= 1.0".to_string());
        }
        let total_w = self.weight_rtt
            + self.weight_error_rate
            + self.weight_throughput
            + self.weight_keepalive;
        if total_w <= 0.0 {
            return Err("at least one metric weight must be > 0".to_string());
        }
        if self.half_life_samples == 0 {
            return Err("half_life_samples must be > 0".to_string());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ScorerConfigBuilder
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct ScorerConfigBuilder {
    config: ScorerConfig,
}

impl ScorerConfigBuilder {
    fn new() -> Self {
        Self {
            config: ScorerConfig::default(),
        }
    }

    pub fn weights(mut self, rtt: f64, err: f64, tp: f64, ka: f64) -> Self {
        self.config.weight_rtt = rtt;
        self.config.weight_error_rate = err;
        self.config.weight_throughput = tp;
        self.config.weight_keepalive = ka;
        self
    }

    pub fn half_life_samples(mut self, n: u64) -> Self {
        self.config.half_life_samples = n;
        self
    }

    pub fn rtt_half_us(mut self, us: f64) -> Self {
        self.config.rtt_half_us = us;
        self
    }

    pub fn expected_throughput(mut self, msgs_per_sec: f64) -> Self {
        self.config.expected_throughput = msgs_per_sec;
        self
    }

    pub fn max_keepalive_misses(mut self, max: u32) -> Self {
        self.config.max_keepalive_misses = max;
        self
    }

    pub fn min_samples_before_active(mut self, n: u64) -> Self {
        self.config.min_samples_before_active = n;
        self
    }

    pub fn thresholds(mut self, suspect: f64, unhealthy: f64, recovery: f64) -> Self {
        self.config.suspect_threshold = suspect;
        self.config.unhealthy_threshold = unhealthy;
        self.config.recovery_threshold = recovery;
        self
    }

    pub fn grace_periods(
        mut self,
        suspect: Duration,
        unhealthy: Duration,
        recovery: Duration,
    ) -> Self {
        self.config.suspect_grace_period = suspect;
        self.config.unhealthy_grace_period = unhealthy;
        self.config.recovery_grace_period = recovery;
        self
    }

    pub fn broadcast_capacity(mut self, cap: usize) -> Self {
        self.config.broadcast_capacity = cap;
        self
    }

    pub fn build(self) -> ScorerConfig {
        self.config
    }
}

// ---------------------------------------------------------------------------
// PeerStatus
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PeerStatus {
    Healthy,
    Suspected,
    Unhealthy,
}

// ---------------------------------------------------------------------------
// PeerStatusTransition
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct PeerStatusTransition {
    pub peer_id: MemberId,
    pub from: PeerStatus,
    pub to: PeerStatus,
    pub score: f64,
    pub at: Instant,
}

// ---------------------------------------------------------------------------
// MetricEwma — internal per-metric EWMA state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct MetricEwma {
    value: f64,
    samples: u64,
}

impl MetricEwma {
    fn new() -> Self {
        Self {
            value: 0.5,
            samples: 0,
        }
    }

    fn update(&mut self, raw: f64, half_life: u64) {
        let alpha = 2.0 / (half_life as f64 + 1.0);
        self.value = alpha * raw + (1.0 - alpha) * self.value;
        self.samples += 1;
    }
}

// ---------------------------------------------------------------------------
// PeerHealthState — per-peer tracking
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PeerHealthState {
    status: PeerStatus,
    rtt_ewma: MetricEwma,
    error_ewma: MetricEwma,
    throughput_ewma: MetricEwma,
    keepalive_ewma: MetricEwma,
    total_messages: u64,
    failed_messages: u64,
    consecutive_misses: u32,
    status_since: Instant,

    below_suspect_since: Option<Instant>,
    below_unhealthy_since: Option<Instant>,
    above_recovery_since: Option<Instant>,
}

impl PeerHealthState {
    fn new(now: Instant) -> Self {
        Self {
            status: PeerStatus::Healthy,
            rtt_ewma: MetricEwma::new(),
            error_ewma: MetricEwma::new(),
            throughput_ewma: MetricEwma::new(),
            keepalive_ewma: MetricEwma::new(),
            total_messages: 0,
            failed_messages: 0,
            consecutive_misses: 0,
            status_since: now,
            below_suspect_since: None,
            below_unhealthy_since: None,
            above_recovery_since: None,
        }
    }

    fn total_samples(&self) -> u64 {
        self.rtt_ewma.samples
            + self.error_ewma.samples
            + self.throughput_ewma.samples
            + self.keepalive_ewma.samples
    }

    fn composite_score(&self, config: &ScorerConfig) -> f64 {
        let total_w = config.weight_rtt
            + config.weight_error_rate
            + config.weight_throughput
            + config.weight_keepalive;
        if total_w <= 0.0 {
            return 1.0;
        }
        let weighted = config.weight_rtt * self.rtt_ewma.value
            + config.weight_error_rate * self.error_ewma.value
            + config.weight_throughput * self.throughput_ewma.value
            + config.weight_keepalive * self.keepalive_ewma.value;
        (weighted / total_w).clamp(0.0, 1.0)
    }

    fn should_transition_to_suspected(
        &self,
        score: f64,
        config: &ScorerConfig,
        now: Instant,
    ) -> bool {
        if self.status != PeerStatus::Healthy {
            return false;
        }
        if self.total_samples() < config.min_samples_before_active {
            return false;
        }
        let below = score < config.suspect_threshold;
        if !below {
            return false;
        }
        let since = self.below_suspect_since.unwrap_or(now);
        now.duration_since(since) >= config.suspect_grace_period
    }

    fn should_transition_to_unhealthy(
        &self,
        score: f64,
        config: &ScorerConfig,
        now: Instant,
    ) -> bool {
        if self.status != PeerStatus::Suspected {
            return false;
        }
        let below = score < config.unhealthy_threshold;
        if !below {
            return false;
        }
        let since = self.below_unhealthy_since.unwrap_or(now);
        now.duration_since(since) >= config.unhealthy_grace_period
    }

    fn should_recover(&self, score: f64, config: &ScorerConfig, now: Instant) -> bool {
        if self.status == PeerStatus::Healthy {
            return false;
        }
        let above = score > config.recovery_threshold;
        if !above {
            return false;
        }
        let since = self.above_recovery_since.unwrap_or(now);
        now.duration_since(since) >= config.recovery_grace_period
    }
}

// ---------------------------------------------------------------------------
// PeerHealthScorer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct PeerHealthScorer {
    inner: Arc<Mutex<ScorerInner>>,
    config: ScorerConfig,
    transition_tx: broadcast::Sender<PeerStatusTransition>,
}

#[derive(Debug)]
struct ScorerInner {
    peers: BTreeMap<MemberId, PeerHealthState>,
}

impl PeerHealthScorer {
    pub fn new(config: ScorerConfig) -> Self {
        let capacity = config.broadcast_capacity;
        let (tx, _) = broadcast::channel(capacity);
        Self {
            inner: Arc::new(Mutex::new(ScorerInner {
                peers: BTreeMap::new(),
            })),
            config,
            transition_tx: tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PeerStatusTransition> {
        self.transition_tx.subscribe()
    }

    pub fn config(&self) -> &ScorerConfig {
        &self.config
    }

    pub fn peer_status(&self, peer_id: MemberId) -> Option<PeerStatus> {
        let inner = self.inner.lock().unwrap();
        inner.peers.get(&peer_id).map(|s| s.status)
    }

    pub fn peer_score(&self, peer_id: MemberId) -> Option<f64> {
        let inner = self.inner.lock().unwrap();
        inner
            .peers
            .get(&peer_id)
            .map(|s| s.composite_score(&self.config))
    }

    pub fn record_rtt(&self, peer_id: MemberId, latency_us: u64) {
        let raw = rtt_subscore(latency_us as f64, self.config.rtt_half_us);
        self.apply_metric(peer_id, |state| {
            state.rtt_ewma.update(raw, self.config.half_life_samples);
        });
    }

    pub fn record_message_result(&self, peer_id: MemberId, success: bool) {
        self.apply_metric(peer_id, |state| {
            state.total_messages += 1;
            if !success {
                state.failed_messages += 1;
            }
            let error_rate = if state.total_messages > 0 {
                state.failed_messages as f64 / state.total_messages as f64
            } else {
                0.0
            };
            let raw = 1.0 - error_rate;
            state.error_ewma.update(raw, self.config.half_life_samples);
        });
    }

    pub fn record_throughput(&self, peer_id: MemberId, messages_per_sec: f64) {
        let raw = throughput_subscore(messages_per_sec, self.config.expected_throughput);
        self.apply_metric(peer_id, |state| {
            state
                .throughput_ewma
                .update(raw, self.config.half_life_samples);
        });
    }

    pub fn record_keepalive_miss(&self, peer_id: MemberId) {
        self.apply_metric(peer_id, |state| {
            state.consecutive_misses += 1;
            let raw =
                keepalive_subscore(state.consecutive_misses, self.config.max_keepalive_misses);
            state
                .keepalive_ewma
                .update(raw, self.config.half_life_samples);
        });
    }

    pub fn record_keepalive_ack(&self, peer_id: MemberId) {
        self.apply_metric(peer_id, |state| {
            state.consecutive_misses = 0;
            state
                .keepalive_ewma
                .update(1.0, self.config.half_life_samples);
        });
    }

    pub fn peer_count(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        inner.peers.len()
    }

    pub fn remove_peer(&self, peer_id: MemberId) {
        let mut inner = self.inner.lock().unwrap();
        inner.peers.remove(&peer_id);
    }

    // ------------------------------------------------------------------
    // Internal
    // ------------------------------------------------------------------

    fn apply_metric(&self, peer_id: MemberId, f: impl FnOnce(&mut PeerHealthState)) {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let state = inner
            .peers
            .entry(peer_id)
            .or_insert_with(|| PeerHealthState::new(now));
        f(state);

        let score = state.composite_score(&self.config);

        // Update threshold-crossing timestamps.
        if score < self.config.suspect_threshold {
            state.below_suspect_since.get_or_insert(now);
        } else {
            state.below_suspect_since = None;
        }
        if score < self.config.unhealthy_threshold {
            state.below_unhealthy_since.get_or_insert(now);
        } else {
            state.below_unhealthy_since = None;
        }
        if score > self.config.recovery_threshold {
            state.above_recovery_since.get_or_insert(now);
        } else {
            state.above_recovery_since = None;
        }

        let old_status = state.status;
        let mut new_status = old_status;

        if state.should_transition_to_suspected(score, &self.config, now) {
            new_status = PeerStatus::Suspected;
        } else if state.should_transition_to_unhealthy(score, &self.config, now) {
            new_status = PeerStatus::Unhealthy;
        } else if state.should_recover(score, &self.config, now) {
            new_status = PeerStatus::Healthy;
        }

        if new_status != old_status {
            state.status = new_status;
            state.status_since = now;
            state.below_suspect_since = None;
            state.below_unhealthy_since = None;
            state.above_recovery_since = None;

            let transition = PeerStatusTransition {
                peer_id,
                from: old_status,
                to: new_status,
                score,
                at: now,
            };
            drop(inner);
            let _ = self.transition_tx.send(transition);
        }
    }
}

// ---------------------------------------------------------------------------
// Sub-score functions (public for testability)
// ---------------------------------------------------------------------------

/// RTT sub-score: exponential decay `exp(-latency_us / half_us)`.
pub fn rtt_subscore(latency_us: f64, half_us: f64) -> f64 {
    if half_us <= 0.0 || latency_us <= 0.0 {
        return 1.0;
    }
    (-latency_us / half_us).exp().clamp(0.0, 1.0)
}

/// Throughput sub-score: ratio of observed to expected throughput.
pub fn throughput_subscore(messages_per_sec: f64, expected: f64) -> f64 {
    if expected <= 0.0 {
        return 1.0;
    }
    (messages_per_sec / expected).clamp(0.0, 1.0)
}

/// Keepalive sub-score: 1.0 minus miss ratio.
pub fn keepalive_subscore(misses: u32, max_misses: u32) -> f64 {
    if max_misses == 0 {
        return 0.0;
    }
    (1.0 - (misses as f64 / max_misses as f64)).clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn make_id(n: u64) -> MemberId {
        MemberId::new(n)
    }

    // -- Config validation --

    #[test]
    fn default_config_is_valid() {
        ScorerConfig::default()
            .validate()
            .expect("default must be valid");
    }

    #[test]
    fn config_rejects_inverted_thresholds() {
        let c = ScorerConfig {
            suspect_threshold: 0.20,
            unhealthy_threshold: 0.50,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_recovery_below_suspect() {
        let c = ScorerConfig {
            recovery_threshold: 0.50,
            suspect_threshold: 0.60,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_all_zero_weights() {
        let c = ScorerConfig {
            weight_rtt: 0.0,
            weight_error_rate: 0.0,
            weight_throughput: 0.0,
            weight_keepalive: 0.0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_zero_half_life() {
        let c = ScorerConfig {
            half_life_samples: 0,
            ..Default::default()
        };
        assert!(c.validate().is_err());
    }

    // -- Sub-score functions --

    #[test]
    fn rtt_zero_is_perfect() {
        assert!((rtt_subscore(0.0, 2000.0) - 1.0).abs() < 0.001);
    }

    #[test]
    fn rtt_at_half_is_exp_neg_one() {
        let s = rtt_subscore(2000.0, 2000.0);
        assert!((s - 0.3679).abs() < 0.01, "got {s}");
    }

    #[test]
    fn rtt_very_large_approaches_zero() {
        assert!(rtt_subscore(1_000_000.0, 2000.0) < 0.001);
    }

    #[test]
    fn throughput_at_expected_is_full() {
        assert!((throughput_subscore(1000.0, 1000.0) - 1.0).abs() < 0.001);
    }

    #[test]
    fn throughput_half_is_half() {
        assert!((throughput_subscore(500.0, 1000.0) - 0.5).abs() < 0.001);
    }

    #[test]
    fn keepalive_zero_misses_is_full() {
        assert!((keepalive_subscore(0, 5) - 1.0).abs() < 0.001);
    }

    #[test]
    fn keepalive_at_max_is_zero() {
        assert!((keepalive_subscore(5, 5) - 0.0).abs() < 0.001);
    }

    // -- Basic scorer operations --

    #[test]
    fn new_scorer_is_empty() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        assert_eq!(scorer.peer_count(), 0);
        assert!(scorer.peer_status(make_id(1)).is_none());
        assert!(scorer.peer_score(make_id(1)).is_none());
    }

    #[test]
    fn record_rtt_creates_peer() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        scorer.record_rtt(make_id(1), 100);
        assert_eq!(scorer.peer_count(), 1);
        assert!(scorer.peer_score(make_id(1)).unwrap() > 0.0);
    }

    #[test]
    fn record_message_result_tracks_error_rate() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        for _ in 0..10 {
            scorer.record_message_result(make_id(1), true);
        }
        let s_all_ok = scorer.peer_score(make_id(1)).unwrap();

        scorer.remove_peer(make_id(1));
        for _ in 0..5 {
            scorer.record_message_result(make_id(1), true);
        }
        for _ in 0..5 {
            scorer.record_message_result(make_id(1), false);
        }
        let s_mixed = scorer.peer_score(make_id(1)).unwrap();
        assert!(s_mixed < s_all_ok);
    }

    #[test]
    fn keepalive_misses_degrade_score() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        scorer.record_keepalive_ack(make_id(1));
        let s_good = scorer.peer_score(make_id(1)).unwrap();
        for _ in 0..5 {
            scorer.record_keepalive_miss(make_id(1));
        }
        let s_bad = scorer.peer_score(make_id(1)).unwrap();
        assert!(s_bad < s_good);
    }

    #[test]
    fn keepalive_ack_resets_misses() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        scorer.record_keepalive_miss(make_id(1));
        scorer.record_keepalive_miss(make_id(1));
        scorer.record_keepalive_miss(make_id(1));
        let s_bad = scorer.peer_score(make_id(1)).unwrap();
        scorer.record_keepalive_ack(make_id(1));
        let s_recovered = scorer.peer_score(make_id(1)).unwrap();
        assert!(s_recovered > s_bad);
    }

    #[test]
    fn remove_peer_cleans_up() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        scorer.record_rtt(make_id(1), 100);
        assert_eq!(scorer.peer_count(), 1);
        scorer.remove_peer(make_id(1));
        assert_eq!(scorer.peer_count(), 0);
        assert!(scorer.peer_score(make_id(1)).is_none());
    }

    // -- Status transitions --

    #[test]
    fn healthy_remains_healthy_with_good_metrics() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        let mut rx = scorer.subscribe();
        for _ in 0..20 {
            scorer.record_rtt(make_id(1), 100);
            scorer.record_message_result(make_id(1), true);
            scorer.record_throughput(make_id(1), 15000.0);
            scorer.record_keepalive_ack(make_id(1));
        }
        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Healthy));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn healthy_to_suspected_after_sustained_poor_score() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(2)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(10),
                Duration::from_millis(5000),
                Duration::from_millis(5000),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100_000);
            scorer.record_message_result(make_id(1), false);
            scorer.record_throughput(make_id(1), 0.0);
            scorer.record_keepalive_miss(make_id(1));
        }

        let score = scorer.peer_score(make_id(1)).unwrap();
        assert!(score < 0.60, "expected score < 0.60, got {score}");

        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);

        let t = rx.try_recv().expect("should emit Healthy->Suspected");
        assert_eq!(t.from, PeerStatus::Healthy);
        assert_eq!(t.to, PeerStatus::Suspected);
        assert_eq!(t.peer_id, make_id(1));
    }

    #[test]
    fn suspected_to_unhealthy_after_prolonged_very_poor_score() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(2)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(5000),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100_000);
            scorer.record_message_result(make_id(1), false);
            scorer.record_throughput(make_id(1), 0.0);
            scorer.record_keepalive_miss(make_id(1));
        }
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);
        let t1 = rx.try_recv().expect("Healthy->Suspected");
        assert_eq!(t1.to, PeerStatus::Suspected);

        // First record after Suspected sets below_unhealthy_since
        scorer.record_rtt(make_id(1), 100_000);
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);
        let t2 = rx.try_recv().expect("Suspected->Unhealthy");
        assert_eq!(t2.from, PeerStatus::Suspected);
        assert_eq!(t2.to, PeerStatus::Unhealthy);
    }

    #[test]
    fn recovery_to_healthy_after_sustained_good_score() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(2)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        // Drive to Unhealthy
        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100_000);
            scorer.record_message_result(make_id(1), false);
            scorer.record_throughput(make_id(1), 0.0);
            scorer.record_keepalive_miss(make_id(1));
        }
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);
        let _ = rx.try_recv(); // Healthy->Suspected
                               // Seed below_unhealthy_since timer then wait for grace period
        scorer.record_rtt(make_id(1), 100_000);
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);
        let _ = rx.try_recv(); // Suspected->Unhealthy
        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Unhealthy));

        // Feed excellent metrics for recovery
        for _ in 0..20 {
            scorer.record_rtt(make_id(1), 50);
            scorer.record_message_result(make_id(1), true);
            scorer.record_throughput(make_id(1), 20000.0);
            scorer.record_keepalive_ack(make_id(1));
        }
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 50);

        let t = rx.try_recv().expect("should recover to Healthy");
        assert_eq!(t.from, PeerStatus::Unhealthy);
        assert_eq!(t.to, PeerStatus::Healthy);
    }

    #[test]
    fn no_flap_short_score_drop_does_not_cause_transition() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(2)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_millis(500),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        // Seed good state
        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100);
            scorer.record_message_result(make_id(1), true);
            scorer.record_throughput(make_id(1), 10000.0);
            scorer.record_keepalive_ack(make_id(1));
        }
        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Healthy));

        // Brief bad sample
        scorer.record_rtt(make_id(1), 500_000);
        scorer.record_message_result(make_id(1), false);

        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Healthy));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn hysteresis_no_immediate_recovery_on_borderline() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(2)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(200),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        // Drive to Suspected
        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100_000);
            scorer.record_message_result(make_id(1), false);
            scorer.record_throughput(make_id(1), 0.0);
            scorer.record_keepalive_miss(make_id(1));
        }
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);
        let _ = rx.try_recv(); // Healthy->Suspected

        // Single good metric — not enough for recovery grace period
        scorer.record_rtt(make_id(1), 50);
        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Suspected));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn insufficient_samples_prevents_transition() {
        let config = ScorerConfig::builder()
            .min_samples_before_active(10)
            .thresholds(0.60, 0.30, 0.70)
            .grace_periods(
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(10),
            )
            .half_life_samples(1)
            .build();
        let scorer = PeerHealthScorer::new(config);
        let mut rx = scorer.subscribe();

        for _ in 0..4 {
            scorer.record_rtt(make_id(1), 100_000);
            scorer.record_message_result(make_id(1), false);
        }
        thread::sleep(Duration::from_millis(20));
        scorer.record_rtt(make_id(1), 100_000);

        assert_eq!(scorer.peer_status(make_id(1)), Some(PeerStatus::Healthy));
        assert!(rx.try_recv().is_err());
    }

    // -- Thread safety --

    #[test]
    fn concurrent_updates_from_multiple_threads() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        let s1 = scorer.clone();
        let s2 = scorer.clone();

        let h1 = thread::spawn(move || {
            for i in 0..100 {
                s1.record_rtt(make_id(1), i * 10);
                s1.record_message_result(make_id(1), true);
            }
        });
        let h2 = thread::spawn(move || {
            for _ in 0..100 {
                s2.record_throughput(make_id(1), 8000.0);
                s2.record_keepalive_ack(make_id(1));
            }
        });
        h1.join().unwrap();
        h2.join().unwrap();

        assert_eq!(scorer.peer_count(), 1);
        assert!(scorer.peer_score(make_id(1)).unwrap() > 0.0);
    }

    // -- Multiple peers --

    #[test]
    fn multiple_peers_independent() {
        let scorer = PeerHealthScorer::new(ScorerConfig::default());
        for _ in 0..10 {
            scorer.record_rtt(make_id(1), 100);
            scorer.record_message_result(make_id(1), true);
            scorer.record_throughput(make_id(1), 10000.0);
            scorer.record_keepalive_ack(make_id(1));
        }
        for _ in 0..10 {
            scorer.record_rtt(make_id(2), 500_000);
            scorer.record_message_result(make_id(2), false);
            scorer.record_throughput(make_id(2), 0.0);
            scorer.record_keepalive_miss(make_id(2));
        }
        let s1 = scorer.peer_score(make_id(1)).unwrap();
        let s2 = scorer.peer_score(make_id(2)).unwrap();
        assert!(s1 > s2, "peer1={s1} must exceed peer2={s2}");
    }

    // -- ScorerConfig builder --

    #[test]
    fn builder_produces_expected_config() {
        let cfg = ScorerConfig::builder()
            .weights(0.4, 0.3, 0.2, 0.1)
            .half_life_samples(16)
            .rtt_half_us(5000.0)
            .expected_throughput(5000.0)
            .max_keepalive_misses(3)
            .min_samples_before_active(20)
            .thresholds(0.55, 0.25, 0.80)
            .grace_periods(
                Duration::from_secs(5),
                Duration::from_secs(10),
                Duration::from_secs(15),
            )
            .broadcast_capacity(128)
            .build();

        assert!((cfg.weight_rtt - 0.4).abs() < 0.001);
        assert_eq!(cfg.half_life_samples, 16);
        assert!((cfg.rtt_half_us - 5000.0).abs() < 0.001);
        assert_eq!(cfg.suspect_grace_period, Duration::from_secs(5));
        assert_eq!(cfg.broadcast_capacity, 128);
    }

    // -- EWMA convergence --

    #[test]
    fn ewma_converges_to_constant_input() {
        let mut ewma = MetricEwma::new();
        for _ in 0..100 {
            ewma.update(0.8, 8);
        }
        assert!((ewma.value - 0.8).abs() < 0.05);
    }

    #[test]
    fn ewma_larger_half_life_smooths_more() {
        let mut fast = MetricEwma::new();
        let mut slow = MetricEwma::new();
        fast.update(0.0, 2);
        slow.update(0.0, 16);
        assert!(fast.value < slow.value);
    }

    // -- Composite score --

    #[test]
    fn composite_score_is_weighted_average() {
        let config = ScorerConfig::builder().weights(1.0, 0.0, 0.0, 0.0).build();
        let mut state = PeerHealthState::new(Instant::now());
        state.rtt_ewma.value = 1.0;
        state.error_ewma.value = 0.0;
        state.throughput_ewma.value = 0.0;
        state.keepalive_ewma.value = 0.0;
        assert!((state.composite_score(&config) - 1.0).abs() < 0.001);
    }

    #[test]
    fn composite_score_equal_weights() {
        let config = ScorerConfig::builder()
            .weights(0.25, 0.25, 0.25, 0.25)
            .build();
        let mut state = PeerHealthState::new(Instant::now());
        state.rtt_ewma.value = 0.8;
        state.error_ewma.value = 0.6;
        state.throughput_ewma.value = 0.4;
        state.keepalive_ewma.value = 0.2;
        let expected = (0.8 + 0.6 + 0.4 + 0.2) / 4.0;
        assert!((state.composite_score(&config) - expected).abs() < 0.001);
    }
}
