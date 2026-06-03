//! Per-replica degradation state machine with hysteresis.
//!
//! Tracks replica-level degradation driven by I/O success/failure
//! and BLAKE3 checksum mismatches. Uses adaptive thresholds to avoid
//! flapping: N consecutive failures to degrade, M consecutive successes
//! to recover, immediate Dead on unrecoverable errors.
//!
//! This is orthogonal to per-chunk ReplicaHealthState — the degradation
//! state machine answers "should we stop sending I/O to this replica?"
//! while the chunk-level tracker answers "is this specific chunk healthy?".

use serde::{Deserialize, Serialize};

/// Simplified replica degradation state for placement/rebuild decisions.
///
/// Four stable states with well-defined transitions:
/// - Healthy: normal I/O, replica receives reads and writes
/// - Degraded: elevated failures, replica is deprioritized but still usable
/// - Dead: unrecoverable or persistent failure, replica excluded from placement
/// - Recovering: recovery in progress after Dead, monitored before returning to Healthy
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum DegradationState {
    Healthy,
    Degraded,
    Dead,
    Recovering,
}

impl DegradationState {
    /// Whether the replica is eligible for new placement.
    pub fn is_placeable(&self) -> bool {
        matches!(self, DegradationState::Healthy | DegradationState::Degraded)
    }

    /// Whether the replica is excluded from all I/O (placement + rebuild source).
    pub fn is_excluded(&self) -> bool {
        matches!(self, DegradationState::Dead)
    }

    /// Whether this state is healthier than another.
    pub fn is_healthier_than(&self, other: DegradationState) -> bool {
        self.ordinal() < other.ordinal()
    }

    fn ordinal(&self) -> u8 {
        match self {
            DegradationState::Healthy => 0,
            DegradationState::Degraded => 1,
            DegradationState::Recovering => 2,
            DegradationState::Dead => 3,
        }
    }
}

impl std::fmt::Display for DegradationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DegradationState::Healthy => write!(f, "healthy"),
            DegradationState::Degraded => write!(f, "degraded"),
            DegradationState::Dead => write!(f, "dead"),
            DegradationState::Recovering => write!(f, "recovering"),
        }
    }
}

/// Configuration for the degradation transition engine.
#[derive(Clone, Debug)]
pub struct DegradationConfig {
    /// Number of consecutive I/O failures to transition Healthy → Degraded.
    pub failure_threshold: u32,
    /// Number of consecutive I/O successes to transition Recovering → Healthy.
    pub recovery_threshold: u32,
    /// Number of consecutive failures in Degraded to transition to Dead.
    pub dead_threshold: u32,
    /// Maximum tolerated BLAKE3 checksum mismatches before immediate Dead.
    /// Exceeding this causes immediate Dead regardless of counter state.
    pub max_checksum_mismatches: u32,
    /// Maximum latency in microseconds before an I/O is considered a failure.
    pub max_latency_us: u64,
}

impl Default for DegradationConfig {
    fn default() -> Self {
        DegradationConfig {
            failure_threshold: 5,
            recovery_threshold: 10,
            dead_threshold: 3,
            max_checksum_mismatches: 1,
            max_latency_us: 100_000, // 100ms
        }
    }
}

/// Hysteresis-aware degradation transition engine.
///
/// Tracks consecutive success/failure counters and applies the state
/// transition rules:
///
/// | From       | Trigger                          | To         |
/// |------------|----------------------------------|------------|
/// | Healthy    | N consecutive failures           | Degraded   |
/// | Healthy    | Unrecoverable error / checksum   | Dead       |
/// | Degraded   | M consecutive failures            | Dead       |
/// | Degraded   | Unrecoverable error / checksum   | Dead       |
/// | Degraded   | Any success                     | Healthy    |
/// | Dead       | First success (enters recovery)  | Recovering |
/// | Recovering | M consecutive successes          | Healthy    |
/// | Recovering | Any failure                     | Degraded   |
#[derive(Clone, Debug)]
pub struct DegradationTransitionEngine {
    config: DegradationConfig,
    state: DegradationState,
    /// Consecutive I/O failures observed (reset on any success).
    consecutive_failures: u32,
    /// Consecutive I/O successes observed (reset on any failure).
    consecutive_successes: u32,
    /// Running count of BLAKE3 checksum mismatches since last state change.
    checksum_mismatches: u32,
    /// Timestamp (ns) of last state transition.
    last_transition_ns: u64,
}

/// Result of feeding an I/O observation to the transition engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionResult {
    /// The new degradation state (may be unchanged).
    pub new_state: DegradationState,
    /// Whether a state transition occurred.
    pub changed: bool,
    /// Reason for the transition or non-transition.
    pub reason: TransitionReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionReason {
    /// No change — counters updated but thresholds not met.
    CountersUpdated,
    /// Unrecoverable error forced immediate Dead.
    UnrecoverableError,
    /// Checksum mismatch count exceeded threshold.
    ChecksumMismatchThreshold,
    /// Failure threshold reached (Healthy → Degraded or Degraded → Dead).
    FailureThresholdReached {
        from: DegradationState,
        to: DegradationState,
    },
    /// Recovery threshold reached (Recovering → Healthy).
    RecoveryThresholdReached,
    /// Single success in Degraded state resets to Healthy.
    DegradedRecovery,
    /// First success after Dead enters Recovering.
    RecoveryStarted,
    /// A failure in Recovering state drops back to Degraded.
    RecoveryFailed,
    /// Replica has been silent (no I/O) past the stale timeout.
    StaleTimeout { timeout_ns: u64, last_seen_ns: u64 },
}

impl DegradationTransitionEngine {
    /// Create a new engine with the given config, starting in Healthy.
    pub fn new(config: DegradationConfig) -> Self {
        DegradationTransitionEngine {
            config,
            state: DegradationState::Healthy,
            consecutive_failures: 0,
            consecutive_successes: 0,
            checksum_mismatches: 0,
            last_transition_ns: 0,
        }
    }

    /// Create a new engine with a known starting state (e.g., after reboot).
    pub fn with_state(config: DegradationConfig, state: DegradationState, now_ns: u64) -> Self {
        DegradationTransitionEngine {
            config,
            state,
            consecutive_failures: 0,
            consecutive_successes: 0,
            checksum_mismatches: 0,
            last_transition_ns: now_ns,
        }
    }

    // ── Accessors ───────────────────────────────────────────────────

    pub fn state(&self) -> DegradationState {
        self.state
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn consecutive_successes(&self) -> u32 {
        self.consecutive_successes
    }

    pub fn checksum_mismatches(&self) -> u32 {
        self.checksum_mismatches
    }

    pub fn last_transition_ns(&self) -> u64 {
        self.last_transition_ns
    }

    // ── I/O observation ─────────────────────────────────────────────

    /// Record a successful I/O operation.
    /// Returns the transition result.
    pub fn record_success(&mut self, now_ns: u64, latency_us: u64) -> TransitionResult {
        // If latency exceeds threshold, treat as failure
        if latency_us > self.config.max_latency_us {
            return self.record_failure(now_ns, false);
        }

        self.consecutive_failures = 0;

        match self.state {
            DegradationState::Healthy => {
                self.consecutive_successes += 1;
                TransitionResult {
                    new_state: DegradationState::Healthy,
                    changed: false,
                    reason: TransitionReason::CountersUpdated,
                }
            }
            DegradationState::Degraded => {
                self.consecutive_successes += 1;
                self.state = DegradationState::Healthy;
                self.consecutive_successes = 0;
                self.checksum_mismatches = 0;
                self.last_transition_ns = now_ns;
                TransitionResult {
                    new_state: DegradationState::Healthy,
                    changed: true,
                    reason: TransitionReason::DegradedRecovery,
                }
            }
            DegradationState::Dead => {
                self.state = DegradationState::Recovering;
                self.consecutive_successes = 1;
                self.consecutive_failures = 0;
                self.checksum_mismatches = 0;
                self.last_transition_ns = now_ns;
                TransitionResult {
                    new_state: DegradationState::Recovering,
                    changed: true,
                    reason: TransitionReason::RecoveryStarted,
                }
            }
            DegradationState::Recovering => {
                self.consecutive_successes += 1;
                if self.consecutive_successes >= self.config.recovery_threshold {
                    self.state = DegradationState::Healthy;
                    self.consecutive_successes = 0;
                    self.last_transition_ns = now_ns;
                    TransitionResult {
                        new_state: DegradationState::Healthy,
                        changed: true,
                        reason: TransitionReason::RecoveryThresholdReached,
                    }
                } else {
                    TransitionResult {
                        new_state: DegradationState::Recovering,
                        changed: false,
                        reason: TransitionReason::CountersUpdated,
                    }
                }
            }
        }
    }

    /// Record a failed I/O operation.
    /// `unrecoverable` indicates a permanent error (e.g., device failure).
    pub fn record_failure(&mut self, now_ns: u64, unrecoverable: bool) -> TransitionResult {
        self.consecutive_successes = 0;
        self.consecutive_failures += 1;

        match self.state {
            DegradationState::Healthy => {
                if unrecoverable {
                    return self
                        .transition_immediate_dead(now_ns, TransitionReason::UnrecoverableError);
                }
                if self.consecutive_failures >= self.config.failure_threshold {
                    self.state = DegradationState::Degraded;
                    self.consecutive_failures = 0;
                    self.last_transition_ns = now_ns;
                    TransitionResult {
                        new_state: DegradationState::Degraded,
                        changed: true,
                        reason: TransitionReason::FailureThresholdReached {
                            from: DegradationState::Healthy,
                            to: DegradationState::Degraded,
                        },
                    }
                } else {
                    TransitionResult {
                        new_state: DegradationState::Healthy,
                        changed: false,
                        reason: TransitionReason::CountersUpdated,
                    }
                }
            }
            DegradationState::Degraded => {
                if unrecoverable {
                    return self
                        .transition_immediate_dead(now_ns, TransitionReason::UnrecoverableError);
                }
                if self.consecutive_failures >= self.config.dead_threshold {
                    self.state = DegradationState::Dead;
                    self.consecutive_failures = 0;
                    self.last_transition_ns = now_ns;
                    TransitionResult {
                        new_state: DegradationState::Dead,
                        changed: true,
                        reason: TransitionReason::FailureThresholdReached {
                            from: DegradationState::Degraded,
                            to: DegradationState::Dead,
                        },
                    }
                } else {
                    TransitionResult {
                        new_state: DegradationState::Degraded,
                        changed: false,
                        reason: TransitionReason::CountersUpdated,
                    }
                }
            }
            DegradationState::Dead => TransitionResult {
                new_state: DegradationState::Dead,
                changed: false,
                reason: TransitionReason::CountersUpdated,
            },
            DegradationState::Recovering => {
                self.state = DegradationState::Degraded;
                self.last_transition_ns = now_ns;
                self.consecutive_failures = 1;
                TransitionResult {
                    new_state: DegradationState::Degraded,
                    changed: true,
                    reason: TransitionReason::RecoveryFailed,
                }
            }
        }
    }

    /// Record a BLAKE3 checksum mismatch.
    /// May cause immediate Dead if threshold exceeded.
    pub fn record_checksum_mismatch(&mut self, now_ns: u64) -> TransitionResult {
        self.checksum_mismatches += 1;

        if self.checksum_mismatches > self.config.max_checksum_mismatches {
            return self
                .transition_immediate_dead(now_ns, TransitionReason::ChecksumMismatchThreshold);
        }

        self.consecutive_successes = 0;
        self.consecutive_failures += 1;

        if self.state == DegradationState::Healthy
            && self.consecutive_failures >= self.config.failure_threshold
        {
            self.state = DegradationState::Degraded;
            self.last_transition_ns = now_ns;
            return TransitionResult {
                new_state: DegradationState::Degraded,
                changed: true,
                reason: TransitionReason::FailureThresholdReached {
                    from: DegradationState::Healthy,
                    to: DegradationState::Degraded,
                },
            };
        }

        TransitionResult {
            new_state: self.state,
            changed: false,
            reason: TransitionReason::CountersUpdated,
        }
    }

    /// Force a state transition (e.g., from admin action or external detector).
    pub fn force_state(&mut self, new_state: DegradationState, now_ns: u64) -> TransitionResult {
        if self.state == new_state {
            return TransitionResult {
                new_state: self.state,
                changed: false,
                reason: TransitionReason::CountersUpdated,
            };
        }
        let old = self.state;
        self.state = new_state;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.checksum_mismatches = 0;
        self.last_transition_ns = now_ns;
        TransitionResult {
            new_state,
            changed: true,
            reason: TransitionReason::FailureThresholdReached {
                from: old,
                to: new_state,
            },
        }
    }

    /// Reset counters without changing state (e.g., epoch change).
    pub fn reset_counters(&mut self) {
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.checksum_mismatches = 0;
    }

    // ── Internal helpers ────────────────────────────────────────────

    fn transition_immediate_dead(
        &mut self,
        now_ns: u64,
        reason: TransitionReason,
    ) -> TransitionResult {
        self.state = DegradationState::Dead;
        self.consecutive_failures = 0;
        self.consecutive_successes = 0;
        self.last_transition_ns = now_ns;
        TransitionResult {
            new_state: DegradationState::Dead,
            changed: true,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> DegradationTransitionEngine {
        DegradationTransitionEngine::new(DegradationConfig::default())
    }

    // ── Healthy → Degraded on failure threshold ─────────────────────

    #[test]
    fn healthy_to_degraded_on_consecutive_failures() {
        let mut eng = engine();
        assert_eq!(eng.state(), DegradationState::Healthy);

        // 4 failures: no transition
        for i in 0..4 {
            let result = eng.record_failure(i * 1000, false);
            assert!(!result.changed);
            assert_eq!(result.new_state, DegradationState::Healthy);
        }

        // 5th failure: transition
        let result = eng.record_failure(5000, false);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Degraded);
        assert_eq!(
            result.reason,
            TransitionReason::FailureThresholdReached {
                from: DegradationState::Healthy,
                to: DegradationState::Degraded
            }
        );
    }

    #[test]
    fn failure_counter_resets_on_success() {
        let mut eng = engine();

        // 3 failures, then a success
        eng.record_failure(1000, false);
        eng.record_failure(2000, false);
        eng.record_failure(3000, false);
        let result = eng.record_success(4000, 100);

        assert!(!result.changed);
        assert_eq!(eng.state(), DegradationState::Healthy);
        assert_eq!(eng.consecutive_failures(), 0);

        // Now 5 more failures needed to degrade
        for i in 0..4 {
            eng.record_failure((5000 + i * 1000) as u64, false);
            assert_eq!(eng.state(), DegradationState::Healthy);
        }
        let result = eng.record_failure(10000, false);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Degraded);
    }

    // ── Immediate Dead on unrecoverable ─────────────────────────────

    #[test]
    fn immediate_dead_on_unrecoverable_from_healthy() {
        let mut eng = engine();
        let result = eng.record_failure(1000, true);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(result.reason, TransitionReason::UnrecoverableError);
    }

    #[test]
    fn immediate_dead_on_unrecoverable_from_degraded() {
        let mut eng = engine();
        // First go to Degraded
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        // Unrecoverable → immediate Dead
        let result = eng.record_failure(6000, true);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
    }

    // ── Degraded → Dead on consecutive failures ─────────────────────

    #[test]
    fn degraded_to_dead_on_consecutive_failures() {
        let mut eng = engine();
        // Get to Degraded
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        // 2 more failures: still Degraded
        eng.record_failure(6000, false);
        eng.record_failure(7000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.consecutive_failures(), 2);

        // 3rd failure in Degraded → Dead
        let result = eng.record_failure(8000, false);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(
            result.reason,
            TransitionReason::FailureThresholdReached {
                from: DegradationState::Degraded,
                to: DegradationState::Dead
            }
        );
    }

    // ── Degraded → Healthy on single success ────────────────────────

    #[test]
    fn degraded_to_healthy_on_single_success() {
        let mut eng = engine();
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        let result = eng.record_success(6000, 100);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Healthy);
        assert_eq!(result.reason, TransitionReason::DegradedRecovery);
        assert_eq!(eng.checksum_mismatches(), 0);
    }

    // ── Dead → Recovering on first success ──────────────────────────

    #[test]
    fn dead_to_recovering_on_first_success() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);

        let result = eng.record_success(2000, 100);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Recovering);
        assert_eq!(result.reason, TransitionReason::RecoveryStarted);
        assert_eq!(eng.consecutive_successes(), 1);
    }

    // ── Recovering → Healthy on recovery threshold ──────────────────

    #[test]
    fn recovering_to_healthy_on_consecutive_successes() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        eng.record_success(2000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);

        // 8 more successes = 9 total (threshold is 10)
        for i in 0..8 {
            let result = eng.record_success((3000 + i * 1000) as u64, 100);
            assert!(!result.changed);
            assert_eq!(eng.state(), DegradationState::Recovering);
        }

        // 10th success: Recovering → Healthy
        let result = eng.record_success(12000, 100);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Healthy);
        assert_eq!(result.reason, TransitionReason::RecoveryThresholdReached);
    }

    // ── Recovering → Degraded on any failure ────────────────────────

    #[test]
    fn recovering_to_degraded_on_failure() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        eng.record_success(2000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);

        // 3 successes into recovery
        eng.record_success(3000, 100);
        eng.record_success(4000, 100);

        // Then a failure → back to Degraded
        let result = eng.record_failure(5000, false);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Degraded);
        assert_eq!(result.reason, TransitionReason::RecoveryFailed);
        assert_eq!(eng.consecutive_failures(), 1);
    }

    // ── Checksum mismatch → immediate Dead ──────────────────────────

    #[test]
    fn checksum_mismatch_immediate_dead() {
        let mut eng = engine();
        assert_eq!(eng.state(), DegradationState::Healthy);

        // First mismatch: counted but no transition (threshold is 1, so >1 means 2)
        let result = eng.record_checksum_mismatch(1000);
        assert!(!result.changed);
        assert_eq!(eng.checksum_mismatches(), 1);

        // Second mismatch: exceeds threshold → Dead
        let result = eng.record_checksum_mismatch(2000);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(result.reason, TransitionReason::ChecksumMismatchThreshold);
    }

    // ── High latency treated as failure ─────────────────────────────

    #[test]
    fn high_latency_is_failure() {
        let mut eng = DegradationTransitionEngine::new(DegradationConfig {
            max_latency_us: 10_000, // 10ms
            ..DegradationConfig::default()
        });

        // High-latency successes become failures (non-unrecoverable)
        for _i in 0..4 {
            eng.record_success(1000, 50_000); // 50ms > 10ms, counted as failure
        }
        assert_eq!(eng.state(), DegradationState::Healthy);
        // 5th high-latency success → Degraded
        eng.record_success(1000, 50_000);
        assert_eq!(eng.state(), DegradationState::Degraded);
    }

    // ── Forced state transitions ────────────────────────────────────

    #[test]
    fn force_state_transition() {
        let mut eng = engine();

        let result = eng.force_state(DegradationState::Dead, 1000);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(eng.consecutive_failures(), 0);
        assert_eq!(eng.consecutive_successes(), 0);

        // Forcing same state is no-op
        let result = eng.force_state(DegradationState::Dead, 2000);
        assert!(!result.changed);
    }

    #[test]
    fn reset_counters_preserves_state() {
        let mut eng = engine();
        for _ in 0..4 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.consecutive_failures(), 4);

        eng.reset_counters();
        assert_eq!(eng.consecutive_failures(), 0);
        assert_eq!(eng.state(), DegradationState::Healthy);

        // Still need 5 failures to transition
        for _ in 0..4 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Healthy);
        eng.record_failure(5000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);
    }

    // ── Dead state absorbs failures ─────────────────────────────────

    #[test]
    fn dead_state_absorbs_failures() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);

        // Failures while Dead don't change anything
        for _ in 0..10 {
            let result = eng.record_failure(2000, false);
            assert!(!result.changed);
            assert_eq!(result.new_state, DegradationState::Dead);
        }
    }

    // ── Placeability and exclusion predicates ───────────────────────

    #[test]
    fn placeability_predicates() {
        assert!(DegradationState::Healthy.is_placeable());
        assert!(DegradationState::Degraded.is_placeable());
        assert!(!DegradationState::Recovering.is_placeable());
        assert!(!DegradationState::Dead.is_placeable());

        assert!(!DegradationState::Healthy.is_excluded());
        assert!(!DegradationState::Degraded.is_excluded());
        assert!(!DegradationState::Recovering.is_excluded());
        assert!(DegradationState::Dead.is_excluded());
    }

    #[test]
    fn health_ordering() {
        assert!(DegradationState::Healthy.is_healthier_than(DegradationState::Degraded));
        assert!(DegradationState::Healthy.is_healthier_than(DegradationState::Recovering));
        assert!(DegradationState::Healthy.is_healthier_than(DegradationState::Dead));
        assert!(DegradationState::Degraded.is_healthier_than(DegradationState::Dead));
        assert!(DegradationState::Recovering.is_healthier_than(DegradationState::Dead));
        assert!(!DegradationState::Dead.is_healthier_than(DegradationState::Healthy));
    }

    // ── Full Healthy → Degraded → Dead → Recovering → Healthy cycle ─

    #[test]
    fn full_degradation_and_recovery_cycle() {
        let mut eng = engine();

        // Healthy → Degraded
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        // Degraded → Dead
        for _ in 0..3 {
            eng.record_failure(2000, false);
        }
        assert_eq!(eng.state(), DegradationState::Dead);

        // Dead → Recovering (first success)
        eng.record_success(3000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);

        // Recovering → Healthy (10 successes)
        for _ in 0..10 {
            eng.record_success(4000, 100);
        }
        assert_eq!(eng.state(), DegradationState::Healthy);
    }

    // ── Custom thresholds ────────────────────────────────────────────

    #[test]
    fn custom_thresholds() {
        let config = DegradationConfig {
            failure_threshold: 3,
            recovery_threshold: 2,
            dead_threshold: 2,
            max_checksum_mismatches: 0, // first mismatch kills
            max_latency_us: 100_000,
        };
        let mut eng = DegradationTransitionEngine::new(config);

        // 3 failures → Degraded (not 5)
        // consecutive_failures resets to 0 on transition
        eng.record_failure(1000, false);
        eng.record_failure(2000, false);
        assert_eq!(eng.state(), DegradationState::Healthy);
        eng.record_failure(3000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.consecutive_failures(), 0);

        // 2 failures → Dead (not 3)
        eng.record_failure(4000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.consecutive_failures(), 1);
        eng.record_failure(5000, false);
        assert_eq!(eng.state(), DegradationState::Dead);
    }
    // ── with_state constructor ──────────────────────────────────────

    #[test]
    fn with_state_starts_in_given_state() {
        let eng = DegradationTransitionEngine::with_state(
            DegradationConfig::default(),
            DegradationState::Degraded,
            5000,
        );
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.last_transition_ns(), 5000);
        assert_eq!(eng.consecutive_failures(), 0);
    }

    #[test]
    fn with_state_dead_remains_dead_until_success() {
        let mut eng = DegradationTransitionEngine::with_state(
            DegradationConfig::default(),
            DegradationState::Dead,
            1000,
        );
        assert_eq!(eng.state(), DegradationState::Dead);
        eng.record_success(2000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);
    }

    // ── Checksum mismatch from Degraded ─────────────────────────────

    #[test]
    fn checksum_mismatch_from_degraded_increments_failures() {
        let mut eng = engine();
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);
        eng.record_checksum_mismatch(6000);
        assert!(eng.consecutive_failures() >= 1);
    }

    #[test]
    fn checksum_mismatch_two_from_degraded_triggers_dead() {
        let mut eng = engine();
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);
        eng.record_checksum_mismatch(6000);
        assert_eq!(eng.state(), DegradationState::Degraded);
        let result = eng.record_checksum_mismatch(7000);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(result.reason, TransitionReason::ChecksumMismatchThreshold);
    }

    // ── Accessor correctness ────────────────────────────────────────

    #[test]
    fn consecutive_failures_accessor_reflects_counter() {
        let mut eng = engine();
        eng.record_failure(1000, false);
        eng.record_failure(2000, false);
        eng.record_failure(3000, false);
        assert_eq!(eng.consecutive_failures(), 3);
        eng.record_success(4000, 100);
        assert_eq!(eng.consecutive_failures(), 0);
    }

    #[test]
    fn consecutive_successes_tracks_accumulation() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        eng.record_success(2000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);
        eng.record_success(3000, 100);
        eng.record_success(4000, 100);
        assert_eq!(eng.consecutive_successes(), 3);
        eng.record_failure(5000, false);
        assert_eq!(eng.consecutive_successes(), 0);
    }

    #[test]
    fn last_transition_ns_updated_on_state_change() {
        let mut eng = engine();
        assert_eq!(eng.last_transition_ns(), 0);
        for i in 0..5 {
            eng.record_failure((i * 1000 + 5000) as u64, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.last_transition_ns(), 9000);
    }

    // ── Success during Healthy ──────────────────────────────────────

    #[test]
    fn success_during_healthy_is_no_op() {
        let mut eng = engine();
        let result = eng.record_success(1000, 50);
        assert!(!result.changed);
        assert_eq!(result.new_state, DegradationState::Healthy);
        assert_eq!(result.reason, TransitionReason::CountersUpdated);
        assert_eq!(eng.consecutive_successes(), 1);
    }

    // ── Failure during Dead ─────────────────────────────────────────

    #[test]
    fn failure_during_dead_is_no_op() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        let result = eng.record_failure(2000, false);
        assert!(!result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(result.reason, TransitionReason::CountersUpdated);
    }

    // ── Recovering success counter reset on failure ─────────────────

    #[test]
    fn recovering_failure_resets_success_counter_to_zero() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        eng.record_success(2000, 100);
        eng.record_success(3000, 100);
        eng.record_success(4000, 100);
        assert_eq!(eng.consecutive_successes(), 3);
        eng.record_failure(5000, false);
        assert_eq!(eng.consecutive_successes(), 0);
    }

    // ── Unrecoverable from Degraded goes immediately Dead ───────────

    #[test]
    fn unrecoverable_from_degraded_is_immediate_dead() {
        let mut eng = engine();
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);
        let result = eng.record_failure(6000, true);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
        assert_eq!(result.reason, TransitionReason::UnrecoverableError);
    }

    // ── Degraded to Healthy clears checksum mismatch state ──────────

    #[test]
    fn degraded_recovery_clears_checksum_mismatches() {
        let mut eng = engine();
        eng.record_checksum_mismatch(1000);
        assert_eq!(eng.checksum_mismatches(), 1);
        for _ in 0..5 {
            eng.record_failure(2000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);
        let result = eng.record_success(3000, 100);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Healthy);
        assert_eq!(eng.checksum_mismatches(), 0);
    }

    // ── Unrecoverable while Dead is redundant but harmless ──────────

    #[test]
    fn unrecoverable_while_dead_is_no_op() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);
        let result = eng.record_failure(2000, true);
        assert!(!result.changed);
        assert_eq!(result.new_state, DegradationState::Dead);
    }

    // ── State machine invariants (property-based) ──────────────────

    /// Verifies that no impossible transitions occur: Dead should only
    /// go to Recovering (via success), never directly to Healthy or Degraded
    /// via failure paths.
    #[test]
    fn invariant_dead_only_exits_via_success() {
        let mut eng = engine();
        eng.force_state(DegradationState::Dead, 1000);

        // Failures keep it in Dead
        for _ in 0..20 {
            let result = eng.record_failure(2000, false);
            assert_eq!(result.new_state, DegradationState::Dead);
            assert!(!result.changed);
        }

        // Only success moves it to Recovering
        let result = eng.record_success(3000, 100);
        assert_eq!(result.new_state, DegradationState::Recovering);
        assert!(result.changed);
    }

    /// Monotonic degradation invariant: without recovery, the replica
    /// should only move in one direction along the degradation axis.
    #[test]
    fn invariant_monotonic_degradation_without_recovery() {
        let mut eng = engine();

        // Drive into Degraded
        for _ in 0..5 {
            eng.record_failure(1000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        // More failures push to Dead
        for _ in 0..3 {
            eng.record_failure(2000, false);
        }
        assert_eq!(eng.state(), DegradationState::Dead);

        // Dead stays Dead on more failures
        for _ in 0..10 {
            let result = eng.record_failure(3000, false);
            assert_eq!(result.new_state, DegradationState::Dead);
        }

        // Success exits Dead -> Recovering
        eng.record_success(4000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);
    }

    /// Idempotent health reports: recording the same outcome multiple
    /// times doesn't cause spurious transitions.
    #[test]
    fn invariant_idempotent_success_during_healthy() {
        let mut eng = engine();

        // Many successes during Healthy do nothing
        for i in 0..50 {
            let result = eng.record_success(i * 100, 50);
            assert_eq!(result.new_state, DegradationState::Healthy);
        }
        assert_eq!(eng.state(), DegradationState::Healthy);
    }

    /// No transitions on zero-op sequences: starting healthy and
    /// interleaving success and failure below thresholds.
    #[test]
    fn invariant_below_threshold_no_transition() {
        let mut eng = engine();

        // 2 failures, 1 success — repeat many times, never hits threshold 5
        for cycle in 0..10 {
            eng.record_failure(cycle * 1000, false);
            eng.record_failure(cycle * 1000 + 100, false);
            eng.record_success(cycle * 1000 + 200, 50);
        }
        assert_eq!(eng.state(), DegradationState::Healthy);
    }

    /// Degraded + single success = Healthy is always true regardless
    /// of how many prior failures occurred in Degraded.
    #[test]
    fn invariant_single_success_recovers_degraded() {
        let config = DegradationConfig {
            failure_threshold: 2,
            dead_threshold: 10, // high — won't trigger Dead
            ..DegradationConfig::default()
        };
        let mut eng = DegradationTransitionEngine::new(config);

        // Enter Degraded
        eng.record_failure(1000, false);
        eng.record_failure(2000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);

        // Several more failures in Degraded (still below dead_threshold)
        for _ in 0..5 {
            eng.record_failure(3000, false);
        }
        assert_eq!(eng.state(), DegradationState::Degraded);

        // Single success -> Healthy
        let result = eng.record_success(4000, 50);
        assert!(result.changed);
        assert_eq!(result.new_state, DegradationState::Healthy);
        assert_eq!(result.reason, TransitionReason::DegradedRecovery);
    }

    /// Checksum mismatches are cumulative and monotonic within a state.
    #[test]
    fn invariant_checksum_mismatch_monotonic() {
        let mut eng = engine();
        assert_eq!(eng.checksum_mismatches(), 0);

        eng.record_checksum_mismatch(1000);
        assert_eq!(eng.checksum_mismatches(), 1);

        eng.record_checksum_mismatch(2000);
        assert_eq!(eng.checksum_mismatches(), 2);

        // But doesn't reset on failure (only state transitions clear it)
        eng.record_failure(3000, false);
        assert_eq!(eng.checksum_mismatches(), 2);
    }

    /// Recovering requires exactly recovery_threshold consecutive successes;
    /// an intervening failure resets the counter.
    #[test]
    fn invariant_recovering_requires_consecutive_successes() {
        let config = DegradationConfig {
            recovery_threshold: 5,
            ..DegradationConfig::default()
        };
        let mut eng = DegradationTransitionEngine::new(config);
        eng.force_state(DegradationState::Dead, 1000);
        eng.record_success(2000, 100);
        assert_eq!(eng.state(), DegradationState::Recovering);

        // 3 more successes = 4 total (threshold is 5)
        for _ in 0..3 {
            eng.record_success(3000, 100);
        }
        assert_eq!(eng.state(), DegradationState::Recovering);

        // A failure resets the success counter and drops to Degraded
        eng.record_failure(4000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);
        assert_eq!(eng.consecutive_successes(), 0);
    }

    /// force_state to a different state resets all counters and clears checksum mismatches.
    #[test]
    fn invariant_force_state_resets_counters() {
        let config = DegradationConfig {
            failure_threshold: 3,
            dead_threshold: 50, // high enough to never trigger
            ..DegradationConfig::default()
        };
        let mut eng = DegradationTransitionEngine::new(config);
        eng.record_checksum_mismatch(1000);
        eng.record_failure(2000, false);
        eng.record_failure(3000, false);
        assert!(eng.checksum_mismatches() > 0);

        // Enter Degraded state (3 failures with custom threshold)
        eng.record_failure(4000, false);
        assert_eq!(eng.state(), DegradationState::Degraded);

        // force_state to Healthy resets everything
        eng.force_state(DegradationState::Healthy, 5000);
        assert_eq!(eng.checksum_mismatches(), 0);
        assert_eq!(eng.consecutive_failures(), 0);
        assert_eq!(eng.consecutive_successes(), 0);
        assert_eq!(eng.state(), DegradationState::Healthy);
    }

    /// Ordinal ordering matches enum definition: Healthy < Degraded < Dead < Recovering.
    #[test]
    fn invariant_ordinal_ordering() {
        assert!(DegradationState::Healthy < DegradationState::Degraded);
        assert!(DegradationState::Degraded < DegradationState::Dead);
        assert!(DegradationState::Dead < DegradationState::Recovering);
    }
}
