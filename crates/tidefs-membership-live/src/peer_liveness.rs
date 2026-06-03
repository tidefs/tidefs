//! Peer liveness state machine driven by transport connection health scores.
//!
//! Bridges [`tidefs_transport::peer_health::LivenessSignal`] into per-peer
//! liveness state tracking so that membership-live can detect peer failures
//! and initiate view changes from real transport validation rather than stubs.
//!
//! ## State Machine
//!
//! ```text
//!   Unknown ──(first score)──> Alive ──(score < suspect)──> Suspect
//!     ^                          |  ^                          |
//!     |    +───(score >= suspect + hyst)───+                    |
//!     |                                                         |
//!     +──(reconnect / reset)────────────────────────────────────+
//!                                                               |
//!     Suspect ──(score < dead)──> Dead ──(score >= suspect + hyst)──> Alive
//! ```
//!
//! Hysteresis prevents rapid state flapping around threshold boundaries:
//! - Descending (Alive -> Suspect): score must drop below
//!   `suspect_threshold - suspect_hysteresis`.
//! - Ascending (Suspect -> Alive): score must rise above
//!   `suspect_threshold + alive_hysteresis`.
//! - Descending (Suspect -> Dead): score must drop below `dead_threshold`.
//! - Ascending (Dead -> Alive): score must rise above
//!   `suspect_threshold + alive_hysteresis`.
//!
//! ## Integration
//!
//! - Transport keepalive and health scoring ([`LivenessSignal`]) feed raw
//!   scores into [`HealthScoreLivenessTracker::update_score`].
//! - Membership view computation can query per-peer state via
//!   [`HealthScoreLivenessTracker::state`] to exclude dead peers.

use std::collections::BTreeMap;
use tidefs_membership_epoch::MemberId;

// ---------------------------------------------------------------------------
// PeerLivenessState
// ---------------------------------------------------------------------------

/// Per-peer liveness state derived from transport health scores.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum PeerLivenessState {
    /// Initial state before any health score is observed.
    Unknown = 0,
    /// Peer is healthy: score is above suspect threshold (with hysteresis on
    /// the ascending edge).
    Alive = 1,
    /// Peer may be failing: score has dropped below suspect threshold but
    /// remains above dead threshold.
    Suspect = 2,
    /// Peer is confirmed dead: score dropped below dead threshold.
    Dead = 3,
}

impl PeerLivenessState {
    /// Whether this state indicates a peer should be excluded from the
    /// active membership view.
    pub fn is_excluded(&self) -> bool {
        matches!(self, PeerLivenessState::Dead)
    }

    /// Whether the peer is in a terminal (non-recoverable-by-score) state.
    /// Dead peers can only recover via an explicit reset (reconnect).
    pub fn is_terminal(&self) -> bool {
        matches!(self, PeerLivenessState::Dead)
    }

    /// Whether the peer is considered alive for membership purposes.
    pub fn is_alive(&self) -> bool {
        matches!(self, PeerLivenessState::Alive)
    }
}

// ---------------------------------------------------------------------------
// HealthScoreLivenessConfig
// ---------------------------------------------------------------------------

/// Configuration for the health-score-driven peer liveness state machine.
///
/// Hysteresis margins prevent oscillation around threshold boundaries:
/// the descending threshold triggers the transition immediately, while the
/// ascending threshold requires crossing `threshold + hysteresis_margin`.
#[derive(Clone, Debug, PartialEq)]
pub struct HealthScoreLivenessConfig {
    /// Score below which an Alive peer becomes Suspect.
    /// Must be > `dead_threshold`.
    pub suspect_threshold: f64,
    /// Score below which a Suspect peer becomes Dead.
    /// Must be < `suspect_threshold`.
    pub dead_threshold: f64,
    /// Additional margin above `suspect_threshold` required to transition
    /// Suspect -> Alive or Dead -> Alive. Prevents flapping.
    pub alive_hysteresis: f64,
    /// Additional margin below `suspect_threshold` required to confirm
    /// the Alive -> Suspect transition in the descending direction.
    /// Default is 0.0 (immediate transition on crossing suspect_threshold).
    pub suspect_hysteresis: f64,
}

impl Default for HealthScoreLivenessConfig {
    fn default() -> Self {
        Self {
            suspect_threshold: 0.4,
            dead_threshold: 0.15,
            alive_hysteresis: 0.1,
            suspect_hysteresis: 0.0,
        }
    }
}

impl HealthScoreLivenessConfig {
    /// Create a new config with default thresholds.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the suspect and dead thresholds.
    #[must_use]
    pub fn with_thresholds(mut self, suspect: f64, dead: f64) -> Self {
        self.suspect_threshold = suspect.clamp(0.0, 1.0);
        self.dead_threshold = dead.clamp(0.0, 1.0);
        self
    }

    /// Set the alive hysteresis margin.
    #[must_use]
    pub fn with_alive_hysteresis(mut self, margin: f64) -> Self {
        self.alive_hysteresis = margin.clamp(0.0, 1.0);
        self
    }

    /// Set the suspect hysteresis margin.
    #[must_use]
    pub fn with_suspect_hysteresis(mut self, margin: f64) -> Self {
        self.suspect_hysteresis = margin.clamp(0.0, 1.0);
        self
    }

    /// Validate that thresholds are consistent
    /// (0.0 <= dead < suspect <= 1.0).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.suspect_threshold < 0.0 || self.suspect_threshold > 1.0 {
            return Err("suspect_threshold must be in [0.0, 1.0]");
        }
        if self.dead_threshold < 0.0 || self.dead_threshold > 1.0 {
            return Err("dead_threshold must be in [0.0, 1.0]");
        }
        if self.dead_threshold >= self.suspect_threshold {
            return Err("dead_threshold must be < suspect_threshold");
        }
        Ok(())
    }

    /// Effective threshold for Alive -> Suspect transition (with hysteresis).
    #[must_use]
    pub fn effective_suspect_down(&self) -> f64 {
        (self.suspect_threshold - self.suspect_hysteresis).max(0.0)
    }

    /// Effective threshold for Suspect -> Alive transition (with hysteresis).
    #[must_use]
    pub fn effective_suspect_up(&self) -> f64 {
        (self.suspect_threshold + self.alive_hysteresis).min(1.0)
    }
}

// ---------------------------------------------------------------------------
// HealthScoreLiveness
// ---------------------------------------------------------------------------

/// Per-peer liveness state machine driven by transport health scores.
///
/// Consumes [`LivenessSignal`] scores and advances through
/// Unknown -> Alive -> Suspect -> Dead based on configurable thresholds
/// with hysteresis to prevent rapid state flapping.
///
/// # Usage
///
/// 1. Update with [`update_score`] each time a new health score is available.
/// 2. Query current state with [`state`].
/// 3. Call [`reset`] to return to Unknown (e.g., on reconnect).
///
/// [`update_score`]: HealthScoreLiveness::update_score
/// [`state`]: HealthScoreLiveness::state
/// [`reset`]: HealthScoreLiveness::reset
pub struct HealthScoreLiveness {
    state: PeerLivenessState,
    config: HealthScoreLivenessConfig,
    /// The last observed score, if any.
    last_score: Option<f64>,
    /// How many consecutive ticks the score has been in the current band.
    consecutive_ticks: u64,
}

impl HealthScoreLiveness {
    /// Create a new liveness tracker for a peer, starting in Unknown state.
    #[must_use]
    pub fn new(config: HealthScoreLivenessConfig) -> Self {
        Self {
            state: PeerLivenessState::Unknown,
            config,
            last_score: None,
            consecutive_ticks: 0,
        }
    }

    /// Update the state machine with a new health score.
    ///
    /// Returns the (possibly unchanged) new state.
    pub fn update_score(&mut self, score: f64) -> PeerLivenessState {
        let clamped = score.clamp(0.0, 1.0);
        self.last_score = Some(clamped);

        let new_state = self.compute_transition(clamped);

        if new_state == self.state {
            self.consecutive_ticks = self.consecutive_ticks.saturating_add(1);
        } else {
            self.consecutive_ticks = 1;
            self.state = new_state;
        }

        self.state
    }

    /// Current liveness state.
    #[must_use]
    pub fn state(&self) -> PeerLivenessState {
        self.state
    }

    /// Last observed health score, if any.
    #[must_use]
    pub fn last_score(&self) -> Option<f64> {
        self.last_score
    }

    /// Number of consecutive updates in the current state (stability counter).
    #[must_use]
    pub fn consecutive_ticks(&self) -> u64 {
        self.consecutive_ticks
    }

    /// Reset to Unknown state (e.g., on transport reconnect).
    pub fn reset(&mut self) {
        self.state = PeerLivenessState::Unknown;
        self.last_score = None;
        self.consecutive_ticks = 0;
    }

    /// Force a specific state (e.g., for testing or operator override).
    pub fn set_state(&mut self, state: PeerLivenessState) {
        self.state = state;
        self.consecutive_ticks = 0;
    }

    // -- private --

    fn compute_transition(&self, score: f64) -> PeerLivenessState {
        let cfg = &self.config;
        let suspect_up = cfg.effective_suspect_up();
        let suspect_down = cfg.effective_suspect_down();

        match self.state {
            PeerLivenessState::Unknown => {
                // First score observed: become Alive regardless of value.
                PeerLivenessState::Alive
            }
            PeerLivenessState::Alive => {
                if score < suspect_down {
                    PeerLivenessState::Suspect
                } else {
                    PeerLivenessState::Alive
                }
            }
            PeerLivenessState::Suspect => {
                if score < cfg.dead_threshold {
                    PeerLivenessState::Dead
                } else if score >= suspect_up {
                    PeerLivenessState::Alive
                } else {
                    PeerLivenessState::Suspect
                }
            }
            PeerLivenessState::Dead => {
                if score >= suspect_up {
                    PeerLivenessState::Alive
                } else {
                    PeerLivenessState::Dead
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HealthScoreLivenessTracker
// ---------------------------------------------------------------------------

/// Multi-peer tracker of health-score-driven liveness state.
///
/// Manages a [`HealthScoreLiveness`] instance per peer, dispatching
/// score updates and exposing state queries for membership view
/// computation.
pub struct HealthScoreLivenessTracker {
    config: HealthScoreLivenessConfig,
    peers: BTreeMap<MemberId, HealthScoreLiveness>,
}

impl HealthScoreLivenessTracker {
    /// Create a new tracker with the given config.
    #[must_use]
    pub fn new(config: HealthScoreLivenessConfig) -> Self {
        Self {
            config,
            peers: BTreeMap::new(),
        }
    }

    /// Register a peer for liveness tracking. No-op if already registered.
    pub fn register_peer(&mut self, member_id: MemberId) {
        self.peers
            .entry(member_id)
            .or_insert_with(|| HealthScoreLiveness::new(self.config.clone()));
    }

    /// Remove a peer from tracking.
    pub fn remove_peer(&mut self, member_id: MemberId) {
        self.peers.remove(&member_id);
    }

    /// Update the health score for a peer. Auto-registers if not
    /// already tracked.
    ///
    /// Returns the new state after the update.
    pub fn update_score(&mut self, member_id: MemberId, score: f64) -> PeerLivenessState {
        let entry = self
            .peers
            .entry(member_id)
            .or_insert_with(|| HealthScoreLiveness::new(self.config.clone()));
        entry.update_score(score)
    }

    /// Get the current state of a peer.
    #[must_use]
    pub fn state(&self, member_id: MemberId) -> Option<PeerLivenessState> {
        self.peers.get(&member_id).map(|p| p.state())
    }

    /// Get the liveness instance for a peer.
    #[must_use]
    pub fn get(&self, member_id: MemberId) -> Option<&HealthScoreLiveness> {
        self.peers.get(&member_id)
    }

    /// Number of tracked peers.
    #[must_use]
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Reset a specific peer to Unknown (e.g., on reconnect).
    pub fn reset_peer(&mut self, member_id: MemberId) {
        if let Some(peer) = self.peers.get_mut(&member_id) {
            peer.reset();
        }
    }

    /// Reset all peers to Unknown.
    pub fn reset_all(&mut self) {
        for peer in self.peers.values_mut() {
            peer.reset();
        }
    }

    /// Iterate over all tracked peers and their current state.
    pub fn iter(&self) -> impl Iterator<Item = (MemberId, PeerLivenessState)> + '_ {
        self.peers.iter().map(|(id, p)| (*id, p.state()))
    }

    /// Collect all peer IDs in a given state.
    pub fn peers_in_state(&self, target: PeerLivenessState) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state() == target)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Collect all alive peer IDs (for membership view computation).
    pub fn alive_peers(&self) -> Vec<MemberId> {
        self.peers
            .iter()
            .filter(|(_, p)| p.state().is_alive())
            .map(|(id, _)| *id)
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use tidefs_transport::peer_health::LivenessSignal;
    // ------------------------------------------------------------------
    // HealthScoreLivenessConfig tests
    // ------------------------------------------------------------------

    #[test]
    fn config_default_is_valid() {
        let cfg = HealthScoreLivenessConfig::default();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn config_rejects_dead_above_suspect() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.3, 0.5);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_dead_equal_to_suspect() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.4);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_effective_thresholds() {
        let cfg = HealthScoreLivenessConfig {
            suspect_threshold: 0.4,
            dead_threshold: 0.15,
            alive_hysteresis: 0.1,
            suspect_hysteresis: 0.05,
        };
        assert!((cfg.effective_suspect_down() - 0.35).abs() < 1e-9);
        assert!((cfg.effective_suspect_up() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn config_effective_thresholds_clamped() {
        let cfg = HealthScoreLivenessConfig {
            suspect_threshold: 0.05,
            dead_threshold: 0.01,
            alive_hysteresis: 0.1,
            suspect_hysteresis: 0.1,
        };
        assert!((cfg.effective_suspect_down() - 0.0).abs() < 1e-9);
        assert!((cfg.effective_suspect_up() - 0.15).abs() < 1e-9);
    }

    #[test]
    fn config_builder_methods() {
        let cfg = HealthScoreLivenessConfig::new()
            .with_thresholds(0.5, 0.2)
            .with_alive_hysteresis(0.15)
            .with_suspect_hysteresis(0.05);
        assert!((cfg.suspect_threshold - 0.5).abs() < 1e-9);
        assert!((cfg.dead_threshold - 0.2).abs() < 1e-9);
        assert!((cfg.alive_hysteresis - 0.15).abs() < 1e-9);
        assert!((cfg.suspect_hysteresis - 0.05).abs() < 1e-9);
    }

    // ------------------------------------------------------------------
    // HealthScoreLiveness state machine tests
    // ------------------------------------------------------------------

    #[test]
    fn initial_state_is_unknown() {
        let liveness = HealthScoreLiveness::new(HealthScoreLivenessConfig::default());
        assert_eq!(liveness.state(), PeerLivenessState::Unknown);
        assert!(liveness.last_score().is_none());
    }

    #[test]
    fn first_score_transitions_to_alive() {
        let mut liveness = HealthScoreLiveness::new(HealthScoreLivenessConfig::default());
        let state = liveness.update_score(0.9);
        assert_eq!(state, PeerLivenessState::Alive);
        assert!(liveness.last_score().is_some());
    }

    #[test]
    fn alive_to_suspect_on_low_score() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // First score: Unknown -> Alive
        liveness.update_score(0.9);
        assert_eq!(liveness.state(), PeerLivenessState::Alive);

        // Drop below suspect_threshold: Alive -> Suspect
        let state = liveness.update_score(0.3);
        assert_eq!(state, PeerLivenessState::Suspect);
    }

    #[test]
    fn suspect_to_dead_on_very_low_score() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Alive -> Suspect
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        assert_eq!(liveness.state(), PeerLivenessState::Suspect);

        // Suspect -> Dead
        let state = liveness.update_score(0.1);
        assert_eq!(state, PeerLivenessState::Dead);
    }

    #[test]
    fn suspect_to_alive_on_recovery() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Alive -> Suspect
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        assert_eq!(liveness.state(), PeerLivenessState::Suspect);

        // Recover above suspect + hysteresis (0.4 + 0.1 = 0.5)
        let state = liveness.update_score(0.55);
        assert_eq!(state, PeerLivenessState::Alive);
    }

    #[test]
    fn suspect_stays_suspect_with_marginal_recovery() {
        let cfg = HealthScoreLivenessConfig::default()
            .with_thresholds(0.4, 0.15)
            .with_alive_hysteresis(0.1);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Alive -> Suspect
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        assert_eq!(liveness.state(), PeerLivenessState::Suspect);

        // Score rises to 0.45: above suspect (0.4) but below suspect+hyst (0.5)
        let state = liveness.update_score(0.45);
        assert_eq!(
            state,
            PeerLivenessState::Suspect,
            "should stay Suspect due to hysteresis"
        );
    }

    #[test]
    fn dead_to_alive_on_strong_recovery() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Drive to Dead
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        liveness.update_score(0.1);
        assert_eq!(liveness.state(), PeerLivenessState::Dead);

        // Strong recovery above suspect + hysteresis
        let state = liveness.update_score(0.6);
        assert_eq!(state, PeerLivenessState::Alive);
    }

    #[test]
    fn dead_stays_dead_with_weak_recovery() {
        let cfg = HealthScoreLivenessConfig::default()
            .with_thresholds(0.4, 0.15)
            .with_alive_hysteresis(0.1);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Drive to Dead
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        liveness.update_score(0.1);
        assert_eq!(liveness.state(), PeerLivenessState::Dead);

        // Score rises to 0.3 but not above suspect+hyst (0.5)
        let state = liveness.update_score(0.3);
        assert_eq!(state, PeerLivenessState::Dead, "should stay Dead");
    }

    #[test]
    fn no_flapping_around_threshold() {
        let cfg = HealthScoreLivenessConfig::default()
            .with_thresholds(0.4, 0.15)
            .with_alive_hysteresis(0.1)
            .with_suspect_hysteresis(0.05);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Establish Alive
        liveness.update_score(0.9);
        assert_eq!(liveness.state(), PeerLivenessState::Alive);

        // Oscillate around suspect_threshold (0.4)
        // suspect_down = 0.35, suspect_up = 0.5
        for i in 0..20 {
            let score = if i % 2 == 0 { 0.45 } else { 0.38 };
            let state = liveness.update_score(score);
            // 0.45 < suspect_up (0.5) AND > suspect_down (0.35) => stays Alive
            // 0.38 > suspect_down (0.35) => stays Alive
            assert_eq!(
                state,
                PeerLivenessState::Alive,
                "should not flap: score={score} never crossed hysteresis margins"
            );
        }
    }

    #[test]
    fn suspect_down_hysteresis_works() {
        let cfg = HealthScoreLivenessConfig {
            suspect_threshold: 0.4,
            dead_threshold: 0.15,
            alive_hysteresis: 0.1,
            suspect_hysteresis: 0.05,
        };
        let mut liveness = HealthScoreLiveness::new(cfg);

        liveness.update_score(0.9);
        assert_eq!(liveness.state(), PeerLivenessState::Alive);

        // Score 0.38: above suspect_down (0.35), so stays Alive
        let state = liveness.update_score(0.38);
        assert_eq!(
            state,
            PeerLivenessState::Alive,
            "0.38 > 0.35 (suspect_down), stays Alive"
        );

        // Score 0.33: below suspect_down (0.35), transitions to Suspect
        let state = liveness.update_score(0.33);
        assert_eq!(state, PeerLivenessState::Suspect);
    }

    #[test]
    fn reset_returns_to_unknown() {
        let mut liveness = HealthScoreLiveness::new(HealthScoreLivenessConfig::default());
        liveness.update_score(0.9);
        liveness.update_score(0.3);
        liveness.update_score(0.1);
        assert_eq!(liveness.state(), PeerLivenessState::Dead);

        liveness.reset();
        assert_eq!(liveness.state(), PeerLivenessState::Unknown);
        assert!(liveness.last_score().is_none());
        assert_eq!(liveness.consecutive_ticks(), 0);
    }

    #[test]
    fn consecutive_ticks_increments() {
        let mut liveness = HealthScoreLiveness::new(HealthScoreLivenessConfig::default());
        liveness.update_score(0.9);
        assert_eq!(liveness.consecutive_ticks(), 1);

        liveness.update_score(0.85);
        assert_eq!(liveness.consecutive_ticks(), 2);

        // Transition resets counter
        liveness.update_score(0.3);
        assert_eq!(liveness.consecutive_ticks(), 1);
    }

    #[test]
    fn set_state_override() {
        let mut liveness = HealthScoreLiveness::new(HealthScoreLivenessConfig::default());
        liveness.update_score(0.9);
        assert_eq!(liveness.state(), PeerLivenessState::Alive);

        liveness.set_state(PeerLivenessState::Dead);
        assert_eq!(liveness.state(), PeerLivenessState::Dead);
        assert_eq!(liveness.consecutive_ticks(), 0);
    }

    // ------------------------------------------------------------------
    // PeerLivenessState tests
    // ------------------------------------------------------------------

    #[test]
    fn state_ordering() {
        assert!(PeerLivenessState::Unknown < PeerLivenessState::Alive);
        assert!(PeerLivenessState::Alive < PeerLivenessState::Suspect);
        assert!(PeerLivenessState::Suspect < PeerLivenessState::Dead);
    }

    #[test]
    fn dead_is_excluded_and_terminal() {
        assert!(PeerLivenessState::Dead.is_excluded());
        assert!(PeerLivenessState::Dead.is_terminal());
        assert!(!PeerLivenessState::Dead.is_alive());
    }

    #[test]
    fn suspect_is_not_excluded() {
        assert!(!PeerLivenessState::Suspect.is_excluded());
        assert!(!PeerLivenessState::Suspect.is_terminal());
        assert!(!PeerLivenessState::Suspect.is_alive());
    }

    #[test]
    fn alive_is_not_excluded() {
        assert!(!PeerLivenessState::Alive.is_excluded());
        assert!(!PeerLivenessState::Alive.is_terminal());
        assert!(PeerLivenessState::Alive.is_alive());
    }

    #[test]
    fn unknown_is_not_excluded() {
        assert!(!PeerLivenessState::Unknown.is_excluded());
        assert!(!PeerLivenessState::Unknown.is_terminal());
        assert!(!PeerLivenessState::Unknown.is_alive());
    }

    // ------------------------------------------------------------------
    // HealthScoreLivenessTracker tests
    // ------------------------------------------------------------------

    #[test]
    fn tracker_registers_and_updates() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        let id = MemberId::new(1);
        tracker.register_peer(id);
        assert_eq!(tracker.peer_count(), 1);
        assert_eq!(tracker.state(id), Some(PeerLivenessState::Unknown));

        // Update pushes to Alive
        let state = tracker.update_score(id, 0.9);
        assert_eq!(state, PeerLivenessState::Alive);
    }

    #[test]
    fn tracker_auto_registers_on_update() {
        let cfg = HealthScoreLivenessConfig::default();
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        let id = MemberId::new(42);
        assert_eq!(tracker.peer_count(), 0);

        let state = tracker.update_score(id, 0.8);
        assert_eq!(state, PeerLivenessState::Alive);
        assert_eq!(tracker.peer_count(), 1);
    }

    #[test]
    fn tracker_removes_peers() {
        let mut tracker = HealthScoreLivenessTracker::new(HealthScoreLivenessConfig::default());
        tracker.register_peer(MemberId::new(1));
        tracker.register_peer(MemberId::new(2));
        assert_eq!(tracker.peer_count(), 2);

        tracker.remove_peer(MemberId::new(1));
        assert_eq!(tracker.peer_count(), 1);
        assert!(tracker.state(MemberId::new(1)).is_none());
    }

    #[test]
    fn tracker_peers_in_state() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        tracker.update_score(MemberId::new(1), 0.9); // Alive
                                                     // First score always transitions Unknown -> Alive
        tracker.update_score(MemberId::new(2), 0.9); // Alive (first score)
        tracker.update_score(MemberId::new(2), 0.3); // Suspect
        tracker.update_score(MemberId::new(3), 0.9); // Alive (first score)
        tracker.update_score(MemberId::new(3), 0.1); // Alive -> Suspect (0.1 < 0.4)
        tracker.update_score(MemberId::new(3), 0.1); // Suspect -> Dead (0.1 < 0.15)

        let alive = tracker.peers_in_state(PeerLivenessState::Alive);
        assert_eq!(alive, vec![MemberId::new(1)]);

        let suspect = tracker.peers_in_state(PeerLivenessState::Suspect);
        assert_eq!(suspect, vec![MemberId::new(2)]);

        let dead = tracker.peers_in_state(PeerLivenessState::Dead);
        assert_eq!(dead, vec![MemberId::new(3)]);
    }

    #[test]
    fn tracker_alive_peers() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        tracker.update_score(MemberId::new(1), 0.9);
        // First score always transitions Unknown -> Alive
        tracker.update_score(MemberId::new(2), 0.9); // Alive (first score)
        tracker.update_score(MemberId::new(2), 0.3); // Suspect
        tracker.update_score(MemberId::new(3), 0.9); // Alive (first score)
        tracker.update_score(MemberId::new(3), 0.1); // Alive -> Suspect
        tracker.update_score(MemberId::new(3), 0.1); // Suspect -> Dead

        let alive = tracker.alive_peers();
        assert_eq!(alive, vec![MemberId::new(1)]);
    }

    #[test]
    fn tracker_reset_peer() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        tracker.update_score(MemberId::new(1), 0.9);
        tracker.update_score(MemberId::new(1), 0.3);
        tracker.update_score(MemberId::new(1), 0.1);
        assert_eq!(
            tracker.state(MemberId::new(1)),
            Some(PeerLivenessState::Dead)
        );

        tracker.reset_peer(MemberId::new(1));
        assert_eq!(
            tracker.state(MemberId::new(1)),
            Some(PeerLivenessState::Unknown)
        );
    }

    #[test]
    fn tracker_reset_all() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        tracker.update_score(MemberId::new(1), 0.9);
        tracker.update_score(MemberId::new(2), 0.3);
        tracker.update_score(MemberId::new(2), 0.1);

        tracker.reset_all();
        assert_eq!(
            tracker.state(MemberId::new(1)),
            Some(PeerLivenessState::Unknown)
        );
        assert_eq!(
            tracker.state(MemberId::new(2)),
            Some(PeerLivenessState::Unknown)
        );
    }

    #[test]
    fn tracker_iter() {
        let mut tracker = HealthScoreLivenessTracker::new(HealthScoreLivenessConfig::default());
        tracker.update_score(MemberId::new(1), 0.9);
        tracker.update_score(MemberId::new(2), 0.9);

        let states: BTreeMap<MemberId, PeerLivenessState> = tracker.iter().collect();
        assert_eq!(states.len(), 2);
        assert_eq!(states[&MemberId::new(1)], PeerLivenessState::Alive);
        assert_eq!(states[&MemberId::new(2)], PeerLivenessState::Alive);
    }

    #[test]
    fn tracker_state_returns_none_for_unknown() {
        let tracker = HealthScoreLivenessTracker::new(HealthScoreLivenessConfig::default());
        assert_eq!(tracker.state(MemberId::new(99)), None);
    }

    // ------------------------------------------------------------------
    // Integration-style: mock LivenessSignal feeding into tracker
    // ------------------------------------------------------------------

    /// A mock signal source for testing without real transport.
    struct MockSignal(f64);

    impl LivenessSignal for MockSignal {
        fn health_score(&self) -> f64 {
            self.0
        }
    }

    #[test]
    fn tracker_driven_by_liveness_signal() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut tracker = HealthScoreLivenessTracker::new(cfg);

        let id = MemberId::new(1);

        // Feed scores via LivenessSignal
        let signals: Vec<MockSignal> = vec![
            MockSignal(0.9),
            MockSignal(0.85),
            MockSignal(0.35), // crosses suspect
            MockSignal(0.1),  // crosses dead
            MockSignal(0.6),  // recovery to alive
        ];

        let expected_states = [
            PeerLivenessState::Alive,
            PeerLivenessState::Alive,
            PeerLivenessState::Suspect,
            PeerLivenessState::Dead,
            PeerLivenessState::Alive,
        ];

        for (signal, expected) in signals.iter().zip(expected_states.iter()) {
            let state = tracker.update_score(id, signal.health_score());
            assert_eq!(
                state, *expected,
                "score={} expected={:?} got={:?}",
                signal.0, expected, state
            );
        }
    }

    // ------------------------------------------------------------------
    // Edge cases
    // ------------------------------------------------------------------

    #[test]
    fn score_clamped_to_range() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Score above 1.0 clamped
        liveness.update_score(1.5);
        assert_eq!(liveness.state(), PeerLivenessState::Alive);

        // Score below 0.0 clamped
        liveness.update_score(-0.5);
        assert_eq!(liveness.state(), PeerLivenessState::Suspect);
        // Third low score: Suspect -> Dead (0.0 < 0.15 dead_threshold)
        liveness.update_score(-0.5);
        assert_eq!(liveness.state(), PeerLivenessState::Dead);
    }

    #[test]
    fn fast_transition_through_all_states() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // Unknown -> Alive
        assert_eq!(liveness.update_score(0.9), PeerLivenessState::Alive);
        // Alive -> Suspect
        assert_eq!(liveness.update_score(0.2), PeerLivenessState::Suspect);
        // Suspect -> Dead
        assert_eq!(liveness.update_score(0.05), PeerLivenessState::Dead);
        // Dead -> Alive (strong recovery)
        assert_eq!(liveness.update_score(0.7), PeerLivenessState::Alive);
    }

    #[test]
    fn zero_score_immediately_dead_from_unknown() {
        let cfg = HealthScoreLivenessConfig::default().with_thresholds(0.4, 0.15);
        let mut liveness = HealthScoreLiveness::new(cfg);

        // First score maps Unknown -> Alive regardless of value
        let state = liveness.update_score(0.0);
        assert_eq!(
            state,
            PeerLivenessState::Alive,
            "first score always transitions to Alive"
        );

        // Second score: Alive -> Suspect (0.0 < 0.4)
        let state = liveness.update_score(0.0);
        assert_eq!(state, PeerLivenessState::Suspect);

        // Third score: Suspect -> Dead (0.0 < 0.15)
        let state = liveness.update_score(0.0);
        assert_eq!(state, PeerLivenessState::Dead);
    }
}
