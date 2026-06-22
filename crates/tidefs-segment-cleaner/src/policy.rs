// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Cleaning policy and backpressure signalling for the segment cleaner.
//!
//! [`CleaningPolicy`] selects the cleaning aggressiveness mode based on
//! the current space-pressure state. [`SegmentScorer`] keeps the cleaner's
//! cost vocabulary available for pressure evidence; `tidefs-compaction` owns
//! partial segment admission and merge ordering.

// ---------------------------------------------------------------------------
// CleaningPolicy
// ---------------------------------------------------------------------------

/// Cleaning aggressiveness mode selected from the current space-pressure
/// state.
///
/// - **Auto**: Normal cleaning cadence, cost-benefit threshold applied.
/// - **Deferred**: Low pressure, cleaning skipped unless a segment is fully
///   dead and releasing it is cheap.
/// - **Urgent**: Space critically low, all eligible segments cleaned
///   regardless of cost-benefit threshold.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleaningPolicy {
    Auto,
    Deferred,
    Urgent,
}

impl CleaningPolicy {
    /// Select a cleaning policy from the pool's free-segment fraction.
    ///
    /// Thresholds:
    /// - `free_fraction < 0.05` → Urgent
    /// - `free_fraction < 0.15` → Auto
    /// - otherwise → Deferred
    #[must_use]
    pub fn from_free_fraction(free_fraction: f64) -> Self {
        if free_fraction < 0.05 {
            Self::Urgent
        } else if free_fraction < 0.15 {
            Self::Auto
        } else {
            Self::Deferred
        }
    }

    /// Whether the cleaner should skip all segments under this policy
    /// (Deferred mode with healthy free space).
    #[must_use]
    pub const fn should_skip(&self) -> bool {
        matches!(self, Self::Deferred)
    }

    /// Whether fully-dead segments should be freed even when Deferred.
    #[must_use]
    pub const fn free_fully_dead(&self) -> bool {
        true
    }

    /// Minimum dead-ratio threshold to apply under this policy,
    /// overriding the configured default when tighter.
    #[must_use]
    pub fn effective_min_dead_ratio(&self, configured: f64) -> f64 {
        match self {
            Self::Urgent => configured.min(0.05),
            Self::Auto => configured,
            Self::Deferred => configured.max(0.70),
        }
    }

    /// Maximum segment age (in transaction groups) to skip under Urgent.
    /// Returns 0, meaning age guard is bypassed entirely.
    #[must_use]
    pub const fn effective_min_age_txg(&self, configured: u64) -> u64 {
        match self {
            Self::Urgent => 0,
            Self::Auto | Self::Deferred => configured,
        }
    }
}

impl Default for CleaningPolicy {
    fn default() -> Self {
        Self::Auto
    }
}

// ---------------------------------------------------------------------------
// CleanerBackpressure
// ---------------------------------------------------------------------------

/// Backpressure signal emitted by the segment cleaner to inform the
/// write path about space-reclamation urgency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanerBackpressure {
    /// No backpressure: normal write admission.
    Normal,
    /// Moderate backpressure: throttle non-critical writes.
    Throttle,
    /// Severe backpressure: reject non-critical writes, only
    /// critical-path writes (intent-log, metadata) admitted.
    RejectNonCritical,
    /// Emergency: all writes rejected until the cleaner frees space.
    RejectAll,
}

impl CleanerBackpressure {
    /// Derive backpressure from the cleaning policy and the fraction
    /// of the pool that is reclaimable dead space.
    #[must_use]
    pub fn from_policy(policy: CleaningPolicy, dead_fraction: f64) -> Self {
        match policy {
            CleaningPolicy::Urgent if dead_fraction > 0.3 => Self::RejectAll,
            CleaningPolicy::Urgent => Self::RejectNonCritical,
            CleaningPolicy::Auto if dead_fraction > 0.5 => Self::Throttle,
            CleaningPolicy::Deferred if dead_fraction > 0.7 => Self::Throttle,
            _ => Self::Normal,
        }
    }
}

// ---------------------------------------------------------------------------
// SegmentScorer -- cleaner cost vocabulary
// ---------------------------------------------------------------------------

/// Computes cost vocabulary for a segment candidate.
///
/// These helpers are evidence inputs only. They do not authorize the segment
/// cleaner to rank, group, or relocate partial live/dead segments; the
/// compaction authority owns those policy decisions.
pub struct SegmentScorer;

impl SegmentScorer {
    /// Compute a cost signal from dead-byte yield and live-byte relocation cost.
    ///
    /// Returns a floating-point score. Higher is better. Fully-dead
    /// segments receive a bonus multiplier.
    #[must_use]
    pub fn score(live_bytes: u64, dead_bytes: u64, is_fully_dead: bool) -> f64 {
        if dead_bytes == 0 {
            return 0.0;
        }
        let base = dead_bytes as f64 / (1.0 + live_bytes as f64);
        if is_fully_dead {
            base * 2.0
        } else {
            base
        }
    }

    /// Score a segment with a write-amplification penalty for young
    /// segments that are still accumulating writes.
    ///
    /// Segments younger than `min_age_txg` relative to `current_txg`
    /// receive a penalty proportional to their youth.
    #[must_use]
    pub fn score_with_age(
        live_bytes: u64,
        dead_bytes: u64,
        is_fully_dead: bool,
        creation_txg: u64,
        current_txg: u64,
        min_age_txg: u64,
    ) -> f64 {
        let base = Self::score(live_bytes, dead_bytes, is_fully_dead);
        if is_fully_dead || min_age_txg == 0 {
            return base;
        }
        let age = current_txg.saturating_sub(creation_txg);
        if age >= min_age_txg {
            return base;
        }
        // Age penalty: linearly scale from 0.0 at age=0 to 1.0 at age=min_age_txg
        let age_factor = age as f64 / min_age_txg as f64;
        base * age_factor
    }

    /// Compute the estimated write amplification for compacting a segment.
    ///
    /// Write amplification = (live + dead) / dead, i.e. how many bytes
    /// must be moved/processed per reclaimed byte. Lower is better.
    #[must_use]
    pub fn write_amplification(live_bytes: u64, dead_bytes: u64) -> f64 {
        if dead_bytes == 0 {
            return f64::INFINITY;
        }
        (live_bytes + dead_bytes) as f64 / dead_bytes as f64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // === CleaningPolicy ===

    #[test]
    fn policy_urgent_below_5pct() {
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.01),
            CleaningPolicy::Urgent
        );
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.049),
            CleaningPolicy::Urgent
        );
    }

    #[test]
    fn policy_auto_between_5_and_15pct() {
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.05),
            CleaningPolicy::Auto
        );
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.10),
            CleaningPolicy::Auto
        );
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.149),
            CleaningPolicy::Auto
        );
    }

    #[test]
    fn policy_deferred_above_15pct() {
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.15),
            CleaningPolicy::Deferred
        );
        assert_eq!(
            CleaningPolicy::from_free_fraction(0.50),
            CleaningPolicy::Deferred
        );
        assert_eq!(
            CleaningPolicy::from_free_fraction(1.0),
            CleaningPolicy::Deferred
        );
    }

    #[test]
    fn policy_should_skip() {
        assert!(!CleaningPolicy::Auto.should_skip());
        assert!(CleaningPolicy::Deferred.should_skip());
        assert!(!CleaningPolicy::Urgent.should_skip());
    }

    #[test]
    fn policy_free_fully_dead_all_modes() {
        assert!(CleaningPolicy::Auto.free_fully_dead());
        assert!(CleaningPolicy::Deferred.free_fully_dead());
        assert!(CleaningPolicy::Urgent.free_fully_dead());
    }

    #[test]
    fn policy_effective_min_dead_ratio() {
        assert_eq!(CleaningPolicy::Auto.effective_min_dead_ratio(0.3), 0.3);
        assert_eq!(CleaningPolicy::Urgent.effective_min_dead_ratio(0.3), 0.05);
        assert_eq!(CleaningPolicy::Deferred.effective_min_dead_ratio(0.3), 0.70);
    }

    #[test]
    fn policy_urgent_lowers_high_threshold() {
        // Urgent should never raise the threshold above 0.05
        assert_eq!(CleaningPolicy::Urgent.effective_min_dead_ratio(0.01), 0.01);
        assert_eq!(CleaningPolicy::Urgent.effective_min_dead_ratio(0.30), 0.05);
    }

    #[test]
    fn policy_deferred_raises_low_threshold() {
        // Deferred should raise low thresholds to at least 0.70
        assert_eq!(
            CleaningPolicy::Deferred.effective_min_dead_ratio(0.10),
            0.70
        );
        assert_eq!(
            CleaningPolicy::Deferred.effective_min_dead_ratio(0.80),
            0.80
        );
    }

    #[test]
    fn policy_effective_min_age_urgent_zero() {
        assert_eq!(CleaningPolicy::Urgent.effective_min_age_txg(5), 0);
    }

    #[test]
    fn policy_effective_min_age_auto_deferred_passthrough() {
        assert_eq!(CleaningPolicy::Auto.effective_min_age_txg(5), 5);
        assert_eq!(CleaningPolicy::Deferred.effective_min_age_txg(5), 5);
    }

    #[test]
    fn policy_default_is_auto() {
        assert_eq!(CleaningPolicy::default(), CleaningPolicy::Auto);
    }

    // === CleanerBackpressure ===

    #[test]
    fn backpressure_normal_on_deferred_healthy() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Deferred, 0.01),
            CleanerBackpressure::Normal
        );
    }

    #[test]
    fn backpressure_throttle_on_deferred_high_dead() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Deferred, 0.71),
            CleanerBackpressure::Throttle
        );
    }

    #[test]
    fn backpressure_throttle_on_auto_high_dead() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Auto, 0.51),
            CleanerBackpressure::Throttle
        );
    }

    #[test]
    fn backpressure_normal_on_auto_low_dead() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Auto, 0.49),
            CleanerBackpressure::Normal
        );
    }

    #[test]
    fn backpressure_reject_all_on_urgent_high_dead() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Urgent, 0.31),
            CleanerBackpressure::RejectAll
        );
    }

    #[test]
    fn backpressure_reject_non_critical_on_urgent_low_dead() {
        assert_eq!(
            CleanerBackpressure::from_policy(CleaningPolicy::Urgent, 0.29),
            CleanerBackpressure::RejectNonCritical
        );
    }

    // === SegmentScorer ===

    #[test]
    fn scorer_zero_dead_returns_zero() {
        assert_eq!(SegmentScorer::score(100, 0, false), 0.0);
    }

    #[test]
    fn scorer_fully_dead_gets_bonus() {
        let normal = SegmentScorer::score(100, 500, false);
        let bonus = SegmentScorer::score(100, 500, true);
        assert!(bonus > normal);
        assert!((bonus - 2.0 * normal).abs() < 0.001);
    }

    #[test]
    fn scorer_higher_dead_higher_score() {
        let low = SegmentScorer::score(100, 100, false);
        let high = SegmentScorer::score(100, 500, false);
        assert!(high > low);
    }

    #[test]
    fn scorer_higher_live_lower_score() {
        let low = SegmentScorer::score(100, 500, false);
        let high = SegmentScorer::score(1000, 500, false);
        assert!(low > high);
    }

    #[test]
    fn scorer_score_with_age_fully_dead_bypasses() {
        let base = SegmentScorer::score(0, 100, true);
        let aged = SegmentScorer::score_with_age(0, 100, true, 1, 100, 50);
        assert!((aged - base).abs() < 0.001);
    }

    #[test]
    fn scorer_score_with_age_old_enough_no_penalty() {
        let base = SegmentScorer::score(100, 500, false);
        let aged = SegmentScorer::score_with_age(100, 500, false, 10, 60, 50);
        assert!((aged - base).abs() < 0.001);
    }

    #[test]
    fn scorer_score_with_age_young_penalized() {
        let base = SegmentScorer::score(100, 500, false);
        let young = SegmentScorer::score_with_age(100, 500, false, 40, 50, 50);
        assert!(young < base);
        assert!(young > 0.0);
    }

    #[test]
    fn scorer_score_with_age_newborn_near_zero() {
        let s = SegmentScorer::score_with_age(100, 500, false, 50, 50, 50);
        assert!(s < 0.01);
    }

    #[test]
    fn scorer_write_amplification_lower_is_better() {
        let wa1 = SegmentScorer::write_amplification(100, 900);
        let wa2 = SegmentScorer::write_amplification(500, 500);
        assert!(wa1 < wa2);
    }

    #[test]
    fn scorer_write_amplification_zero_dead_infinite() {
        assert!(SegmentScorer::write_amplification(100, 0).is_infinite());
    }

    #[test]
    fn scorer_write_amplification_fully_dead_is_one() {
        assert!((SegmentScorer::write_amplification(0, 100) - 1.0).abs() < 0.001);
    }

    #[test]
    fn backpressure_derivation_consistent() {
        // A consistent system: the more urgent and the more dead,
        // the more restrictive the backpressure.
        let bp1 = CleanerBackpressure::from_policy(CleaningPolicy::Deferred, 0.1);
        let bp2 = CleanerBackpressure::from_policy(CleaningPolicy::Auto, 0.1);
        let bp3 = CleanerBackpressure::from_policy(CleaningPolicy::Urgent, 0.1);
        let bp4 = CleanerBackpressure::from_policy(CleaningPolicy::Urgent, 0.5);

        assert_eq!(bp1, CleanerBackpressure::Normal);
        assert_eq!(bp2, CleanerBackpressure::Normal);
        assert_eq!(bp3, CleanerBackpressure::RejectNonCritical);
        assert_eq!(bp4, CleanerBackpressure::RejectAll);
    }
}
