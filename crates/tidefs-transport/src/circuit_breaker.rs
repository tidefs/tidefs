//! Transport circuit breaker with per-peer failure tracking, half-open
//! probing, and domain-separated state-digest verification via BLAKE3.
//!
//! ## Purpose
//!
//! The circuit breaker prevents cascading resource exhaustion by halting
//! message dispatch to persistently failing peers. When a peer exceeds a
//! configurable consecutive failure threshold, the circuit opens and all
//! subsequent requests are immediately rejected without attempting delivery.
//!
//! ## State machine
//!
//! ```text
//!                  record_failure() N times
//!   +----------+  -------------------------->  +------+
//!   |  Closed  |                                | Open |
//!   | (normal) |  <---------------------------  |(fail)|
//!   +----------+  record_success() after probe  +------+
//!        ^                                        |
//!        |          cooldown expires               |
//!        |  +------------+                        |
//!        +--| HalfOpen   |<-----------------------+
//!           | (probing)  |
//!           +------------+
//!                |  record_failure()
//!                +-------------------------->  Open
//! ```
//!
//! - **Closed**: normal dispatch; tracks consecutive failures.
//!   Transitions to Open after `failure_threshold` consecutive failures.
//! - **Open**: all requests rejected. Transitions to HalfOpen after
//!   `cooldown_duration` expires.
//! - **HalfOpen**: limited probing (up to `max_half_open_probes`).
//!   First success -> Closed; any failure -> Open.
//!
//! ## BLAKE3 integrity
//!
//! Each peer circuit exposes a [`PeerCircuit::state_digest()`] that computes
//! a BLAKE3-256 hash over (peer_id, state discriminant, consecutive_failures,
//! half_open_probes_used) with domain `tidefs-transport-circuit-breaker-v1`.
//! This enables external auditing of circuit state consistency across nodes.
//!
//! ## Integration
//!
//! The circuit breaker is designed to be wired into [`MessageDispatcher`]
//! (crate::message_dispatch) to gate dispatch per-peer. Before calling
//! the handler, the dispatcher queries `allow_request(peer_id)`; if
//! rejected, the message is dropped and counted.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Domain-separation constant
// ---------------------------------------------------------------------------

/// Domain context for BLAKE3 circuit-state hashing.
const CIRCUIT_DOMAIN: &str = "tidefs-transport-circuit-breaker-v1";

// ---------------------------------------------------------------------------
// PeerId -- identifies a remote peer for circuit tracking
// ---------------------------------------------------------------------------

/// Identifies a remote peer for circuit breaker tracking.
///
/// Consistent with the `peer_node: u64` field in
/// [`Session`](crate::session::Session).
pub type PeerId = u64;

// ---------------------------------------------------------------------------
// CircuitState
// ---------------------------------------------------------------------------

/// Circuit breaker state for a single peer.
///
/// See [module-level documentation](self) for the full state machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation; dispatch allowed.
    Closed,
    /// Failure threshold exceeded; all dispatch rejected.
    Open,
    /// Probing recovery; limited dispatch allowed.
    HalfOpen,
}

impl CircuitState {
    /// State discriminant used in BLAKE3 digest computation.
    fn discriminant(self) -> u8 {
        match self {
            CircuitState::Closed => 0,
            CircuitState::Open => 1,
            CircuitState::HalfOpen => 2,
        }
    }
}

impl fmt::Display for CircuitState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "Closed"),
            CircuitState::Open => write!(f, "Open"),
            CircuitState::HalfOpen => write!(f, "HalfOpen"),
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitDecision
// ---------------------------------------------------------------------------

/// Outcome of a circuit breaker dispatch check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CircuitDecision {
    /// Request is allowed to proceed.
    Allowed,
    /// Request is rejected; circuit is open or probe capacity exhausted.
    Rejected,
}

// ---------------------------------------------------------------------------
// CircuitBreakerConfig
// ---------------------------------------------------------------------------

/// Configuration for the circuit breaker.
#[derive(Clone, Debug)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration to wait before transitioning from Open to HalfOpen.
    pub cooldown_duration: Duration,
    /// Maximum number of requests allowed in HalfOpen state for probing.
    pub max_half_open_probes: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            cooldown_duration: Duration::from_secs(30),
            max_half_open_probes: 1,
        }
    }
}

// ---------------------------------------------------------------------------
// PeerCircuit -- per-peer circuit breaker state
// ---------------------------------------------------------------------------

/// Per-peer circuit breaker tracking state.
#[derive(Clone, Debug)]
pub struct PeerCircuit {
    /// Circuit state: Closed, Open, or HalfOpen.
    pub state: CircuitState,
    /// Consecutive failure count (reset on success in Closed state).
    pub consecutive_failures: u32,
    /// Instant when the circuit last transitioned to Open.
    /// Used to compute cooldown expiry.
    pub opened_at: Option<Instant>,
    /// Number of half-open probes used in the current HalfOpen window.
    pub half_open_probes_used: u32,
    /// Peer identifier.
    pub peer_id: PeerId,
    /// Maximum half-open probes allowed (from config, captured at creation).
    max_half_open_probes: u32,
}

impl PeerCircuit {
    /// Create a new peer circuit in Closed state.
    pub fn new(peer_id: PeerId, max_half_open_probes: u32) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: None,
            half_open_probes_used: 0,
            peer_id,
            max_half_open_probes,
        }
    }

    /// Compute a BLAKE3-256 state digest for integrity verification.
    ///
    /// The digest covers (peer_id, state discriminant, consecutive_failures,
    /// half_open_probes_used) with domain
    /// `tidefs-transport-circuit-breaker-v1`.
    pub fn state_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CIRCUIT_DOMAIN.as_bytes());
        hasher.update(&self.peer_id.to_le_bytes());
        hasher.update(&[self.state.discriminant()]);
        hasher.update(&self.consecutive_failures.to_le_bytes());
        hasher.update(&self.half_open_probes_used.to_le_bytes());
        *hasher.finalize().as_bytes()
    }
}

// ---------------------------------------------------------------------------
// CircuitBreaker -- global circuit breaker manager
// ---------------------------------------------------------------------------

/// Manages circuit breaker state for all peers.
///
/// Callers must provide external synchronization (e.g. `Mutex<CircuitBreaker>`).
#[derive(Clone, Debug)]
pub struct CircuitBreaker {
    /// Per-peer circuit state.
    circuits: HashMap<PeerId, PeerCircuit>,
    /// Configuration.
    config: CircuitBreakerConfig,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            circuits: HashMap::new(),
            config,
        }
    }

    /// Return the number of tracked peers.
    pub fn peer_count(&self) -> usize {
        self.circuits.len()
    }

    /// Return the configuration.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Check whether a request to `peer_id` is allowed.
    ///
    /// Returns [`CircuitDecision::Allowed`] if the circuit is closed or if a
    /// half-open probe slot is available. The caller must call
    /// [`record_success`](Self::record_success) or
    /// [`record_failure`](Self::record_failure) after the request completes.
    pub fn allow_request(&mut self, peer_id: PeerId) -> CircuitDecision {
        let config = &self.config;
        let circuit = self
            .circuits
            .entry(peer_id)
            .or_insert_with(|| PeerCircuit::new(peer_id, config.max_half_open_probes));

        match circuit.state {
            CircuitState::Closed => CircuitDecision::Allowed,
            CircuitState::Open => {
                Self::check_cooldown(circuit, self.config.cooldown_duration);
                match circuit.state {
                    CircuitState::HalfOpen => {
                        if circuit.half_open_probes_used < circuit.max_half_open_probes {
                            circuit.half_open_probes_used += 1;
                            CircuitDecision::Allowed
                        } else {
                            CircuitDecision::Rejected
                        }
                    }
                    _ => CircuitDecision::Rejected,
                }
            }
            CircuitState::HalfOpen => {
                if circuit.half_open_probes_used < circuit.max_half_open_probes {
                    circuit.half_open_probes_used += 1;
                    CircuitDecision::Allowed
                } else {
                    CircuitDecision::Rejected
                }
            }
        }
    }

    /// Record a successful request to `peer_id`.
    ///
    /// In Closed state, resets consecutive failures. In HalfOpen state,
    /// transitions back to Closed.
    pub fn record_success(&mut self, peer_id: PeerId) {
        let config = &self.config;
        let circuit = self
            .circuits
            .entry(peer_id)
            .or_insert_with(|| PeerCircuit::new(peer_id, config.max_half_open_probes));

        match circuit.state {
            CircuitState::Closed => {
                circuit.consecutive_failures = 0;
            }
            CircuitState::HalfOpen => {
                circuit.state = CircuitState::Closed;
                circuit.consecutive_failures = 0;
                circuit.half_open_probes_used = 0;
                circuit.opened_at = None;
            }
            CircuitState::Open => {
                circuit.state = CircuitState::Closed;
                circuit.consecutive_failures = 0;
                circuit.half_open_probes_used = 0;
                circuit.opened_at = None;
            }
        }
    }

    /// Record a failed request to `peer_id`.
    ///
    /// In Closed state, increments consecutive failures and opens the
    /// circuit when the threshold is reached. In HalfOpen state, immediately
    /// re-opens the circuit. In Open state, resets the cooldown timer.
    pub fn record_failure(&mut self, peer_id: PeerId) {
        let config = &self.config;
        let circuit = self
            .circuits
            .entry(peer_id)
            .or_insert_with(|| PeerCircuit::new(peer_id, config.max_half_open_probes));

        match circuit.state {
            CircuitState::Closed => {
                circuit.consecutive_failures += 1;
                if circuit.consecutive_failures >= config.failure_threshold {
                    circuit.state = CircuitState::Open;
                    circuit.opened_at = Some(Instant::now());
                    circuit.half_open_probes_used = 0;
                }
            }
            CircuitState::HalfOpen => {
                circuit.state = CircuitState::Open;
                circuit.opened_at = Some(Instant::now());
                circuit.half_open_probes_used = 0;
                circuit.consecutive_failures = config.failure_threshold;
            }
            CircuitState::Open => {
                circuit.opened_at = Some(Instant::now());
                circuit.consecutive_failures = config.failure_threshold;
            }
        }
    }

    /// Get the current circuit state for a peer.
    ///
    /// Returns `None` if the peer has never been tracked.
    /// Record a backpressure event for a peer without incrementing failure counters.
    ///
    /// This is a soft signal (e.g., send buffer full) distinct from a
    /// hard failure that would open the circuit. It ensures the peer is
    /// tracked but does not count against the failure threshold.
    pub fn record_backpressure(&mut self, peer_id: PeerId) {
        let config = &self.config;
        self.circuits
            .entry(peer_id)
            .or_insert_with(|| PeerCircuit::new(peer_id, config.max_half_open_probes));
        // Intentionally does not increment consecutive_failures.
    }

    pub fn peer_state(&self, peer_id: PeerId) -> Option<CircuitState> {
        self.circuits.get(&peer_id).map(|c| c.state)
    }

    /// Get the consecutive failure count for a peer.
    ///
    /// Returns `None` if the peer has never been tracked.
    pub fn peer_failures(&self, peer_id: PeerId) -> Option<u32> {
        self.circuits.get(&peer_id).map(|c| c.consecutive_failures)
    }

    /// Remove a peer from tracking (e.g., after permanent disconnect).
    pub fn remove_peer(&mut self, peer_id: PeerId) -> Option<PeerCircuit> {
        self.circuits.remove(&peer_id)
    }

    /// Compute a BLAKE3-256 aggregate digest over all tracked peers.
    ///
    /// Hashes (peer_count, then each peer's state_digest in sorted peer_id
    /// order) with the circuit breaker domain.
    pub fn aggregate_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(CIRCUIT_DOMAIN.as_bytes());
        hasher.update(b":aggregate");
        hasher.update(&(self.circuits.len() as u64).to_le_bytes());

        let mut peer_ids: Vec<PeerId> = self.circuits.keys().copied().collect();
        peer_ids.sort_unstable();
        for peer_id in peer_ids {
            if let Some(circuit) = self.circuits.get(&peer_id) {
                hasher.update(&circuit.state_digest());
            }
        }

        *hasher.finalize().as_bytes()
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    /// Check if the cooldown has expired for an Open circuit and transition
    /// to HalfOpen if it has.
    fn check_cooldown(circuit: &mut PeerCircuit, cooldown: Duration) {
        if circuit.state != CircuitState::Open {
            return;
        }
        if let Some(opened_at) = circuit.opened_at {
            if opened_at.elapsed() >= cooldown {
                circuit.state = CircuitState::HalfOpen;
                circuit.half_open_probes_used = 0;
            }
        }
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn fast_breaker() -> CircuitBreaker {
        CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown_duration: Duration::from_millis(1),
            max_half_open_probes: 1,
        })
    }

    // -- State transitions --

    #[test]
    fn new_circuit_untracked() {
        let cb = CircuitBreaker::default();
        assert_eq!(cb.peer_state(42), None);
    }

    #[test]
    fn closed_allows_request() {
        let mut cb = CircuitBreaker::default();
        assert_eq!(cb.allow_request(1), CircuitDecision::Allowed);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Closed));
    }

    #[test]
    fn success_resets_consecutive_failures() {
        let mut cb = CircuitBreaker::default();
        cb.record_failure(1);
        cb.record_failure(1);
        assert_eq!(cb.peer_failures(1), Some(2));
        cb.record_success(1);
        assert_eq!(cb.peer_failures(1), Some(0));
    }

    #[test]
    fn closed_to_open_at_threshold() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            cooldown_duration: Duration::from_secs(60),
            max_half_open_probes: 1,
        });
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Closed));
        cb.record_failure(1);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));
    }

    #[test]
    fn open_rejects_all_requests() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_duration: Duration::from_secs(60),
            max_half_open_probes: 1,
        });
        cb.record_failure(1);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));
        assert_eq!(cb.allow_request(1), CircuitDecision::Rejected);
    }

    #[test]
    fn open_to_halfopen_after_cooldown() {
        let mut cb = fast_breaker();
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        cb.record_failure(1);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));

        std::thread::sleep(Duration::from_millis(5));

        let d = cb.allow_request(1);
        assert_eq!(d, CircuitDecision::Allowed);
        assert_eq!(cb.peer_state(1), Some(CircuitState::HalfOpen));
    }

    #[test]
    fn halfopen_success_closes_circuit() {
        let mut cb = fast_breaker();
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        cb.record_failure(1);
        std::thread::sleep(Duration::from_millis(5));

        cb.allow_request(1);
        cb.record_success(1);

        assert_eq!(cb.peer_state(1), Some(CircuitState::Closed));
        assert_eq!(cb.peer_failures(1), Some(0));
    }

    #[test]
    fn halfopen_failure_reopens_circuit() {
        let mut cb = fast_breaker();
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        cb.record_failure(1);
        std::thread::sleep(Duration::from_millis(5));

        cb.allow_request(1);
        cb.record_failure(1);

        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));
    }

    #[test]
    fn open_resets_cooldown_on_halfopen_failure() {
        let mut cb = fast_breaker();
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        cb.record_failure(1);
        std::thread::sleep(Duration::from_millis(5));

        assert_eq!(cb.allow_request(1), CircuitDecision::Allowed);
        assert_eq!(cb.peer_state(1), Some(CircuitState::HalfOpen));

        cb.record_failure(1);
        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));
        assert_eq!(cb.allow_request(1), CircuitDecision::Rejected);
    }

    // -- Peer isolation --

    #[test]
    fn independent_peer_states() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            cooldown_duration: Duration::from_secs(60),
            max_half_open_probes: 1,
        });
        cb.allow_request(1);
        cb.record_failure(1);
        cb.record_failure(1);
        cb.allow_request(2);
        cb.record_success(2);

        assert_eq!(cb.peer_state(1), Some(CircuitState::Open));
        assert_eq!(cb.peer_state(2), Some(CircuitState::Closed));
    }

    // -- Half-open probe limits --

    #[test]
    fn halfopen_probe_exhaustion() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            cooldown_duration: Duration::from_millis(1),
            max_half_open_probes: 2,
        });
        cb.allow_request(1);
        cb.record_failure(1);
        std::thread::sleep(Duration::from_millis(20));

        assert_eq!(cb.allow_request(1), CircuitDecision::Allowed);
        assert_eq!(cb.allow_request(1), CircuitDecision::Allowed);
        assert_eq!(cb.allow_request(1), CircuitDecision::Rejected);
    }

    // -- BLAKE3 digest consistency --

    #[test]
    fn state_digest_deterministic() {
        let c = PeerCircuit {
            state: CircuitState::Closed,
            consecutive_failures: 2,
            opened_at: None,
            half_open_probes_used: 0,
            peer_id: 42,
            max_half_open_probes: 1,
        };
        assert_eq!(c.state_digest(), c.state_digest());
    }

    #[test]
    fn state_digest_varies_with_state() {
        let c_closed = PeerCircuit {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            opened_at: None,
            half_open_probes_used: 0,
            peer_id: 1,
            max_half_open_probes: 1,
        };
        let c_open = PeerCircuit {
            state: CircuitState::Open,
            consecutive_failures: 3,
            opened_at: Some(Instant::now()),
            half_open_probes_used: 0,
            peer_id: 1,
            max_half_open_probes: 1,
        };
        let c_half = PeerCircuit {
            state: CircuitState::HalfOpen,
            consecutive_failures: 3,
            opened_at: Some(Instant::now()),
            half_open_probes_used: 1,
            peer_id: 1,
            max_half_open_probes: 1,
        };
        assert_ne!(c_closed.state_digest(), c_open.state_digest());
        assert_ne!(c_closed.state_digest(), c_half.state_digest());
        assert_ne!(c_open.state_digest(), c_half.state_digest());
    }

    #[test]
    fn state_digest_varies_with_peer_id() {
        let c1 = PeerCircuit::new(1, 1);
        let c2 = PeerCircuit::new(2, 1);
        assert_ne!(c1.state_digest(), c2.state_digest());
    }

    #[test]
    fn aggregate_digest_idempotent() {
        let mut cb = CircuitBreaker::default();
        cb.allow_request(10);
        cb.record_failure(10);
        cb.allow_request(20);
        cb.record_success(20);
        assert_eq!(cb.aggregate_digest(), cb.aggregate_digest());
    }

    #[test]
    fn aggregate_digest_changes_with_new_peer() {
        let mut cb = CircuitBreaker::default();
        cb.allow_request(1);
        let d1 = cb.aggregate_digest();
        cb.allow_request(2);
        assert_ne!(d1, cb.aggregate_digest());
    }

    #[test]
    fn aggregate_digest_changes_with_state_transition() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 2,
            cooldown_duration: Duration::from_secs(60),
            max_half_open_probes: 1,
        });
        cb.allow_request(1);
        let d1 = cb.aggregate_digest();
        cb.record_failure(1);
        assert_ne!(d1, cb.aggregate_digest());
    }

    // -- remove_peer --

    #[test]
    fn remove_peer_drops_tracking() {
        let mut cb = CircuitBreaker::default();
        cb.allow_request(1);
        cb.record_failure(1);
        assert_eq!(cb.peer_count(), 1);
        assert!(cb.remove_peer(1).is_some());
        assert_eq!(cb.peer_count(), 0);
    }

    #[test]
    fn remove_nonexistent_returns_none() {
        let mut cb = CircuitBreaker::default();
        assert!(cb.remove_peer(99).is_none());
    }

    // -- Edge cases --

    #[test]
    fn success_creates_untracked_peer() {
        let mut cb = CircuitBreaker::default();
        cb.record_success(99);
        assert_eq!(cb.peer_state(99), Some(CircuitState::Closed));
        assert_eq!(cb.peer_failures(99), Some(0));
    }

    #[test]
    fn failure_creates_untracked_peer() {
        let mut cb = CircuitBreaker::default();
        cb.record_failure(99);
        assert_eq!(cb.peer_state(99), Some(CircuitState::Closed));
        assert_eq!(cb.peer_failures(99), Some(1));
    }

    #[test]
    fn below_threshold_stays_closed() {
        let mut cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 5,
            cooldown_duration: Duration::from_secs(60),
            max_half_open_probes: 1,
        });
        cb.allow_request(1);
        for _ in 0..4 {
            cb.record_failure(1);
        }
        assert_eq!(cb.peer_state(1), Some(CircuitState::Closed));
    }

    #[test]
    fn full_closed_open_halfopen_closed_cycle() {
        let mut cb = fast_breaker();
        let peer: PeerId = 7;

        cb.allow_request(peer);
        cb.record_failure(peer);
        cb.record_failure(peer);
        cb.record_failure(peer);
        assert_eq!(cb.peer_state(peer), Some(CircuitState::Open));

        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cb.allow_request(peer), CircuitDecision::Allowed);
        assert_eq!(cb.peer_state(peer), Some(CircuitState::HalfOpen));

        cb.record_success(peer);
        assert_eq!(cb.peer_state(peer), Some(CircuitState::Closed));
        assert_eq!(cb.peer_failures(peer), Some(0));
    }

    // -- BLAKE3 domain separation --

    #[test]
    fn domain_separation_alters_hash() {
        let circuit = PeerCircuit::new(42, 1);
        let d1 = circuit.state_digest();

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"tidefs-transport-other-domain-v1");
        hasher.update(&42u64.to_le_bytes());
        hasher.update(&[0u8]);
        hasher.update(&0u32.to_le_bytes());
        hasher.update(&0u32.to_le_bytes());
        let d2 = *hasher.finalize().as_bytes();

        assert_ne!(d1, d2);
    }
}
