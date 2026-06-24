// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Shared heuristic types for relocation action classification, HDD/SSD/WAN
//! heuristics, and prediction confidence.


use crate::reasons::GovernorRelocationReason;

// ── Relocation action class ──────────────────────────────────────────

/// Action class for relocation decisions.
///
/// Determines what kind of relocation can be performed. Higher classes
/// require more evidence and are more durable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[repr(u8)]
pub enum RelocationActionClass {
    /// No action: the governor cannot act on this candidate.
    None = 0,

    /// Cache-only serving trial: droppable, non-authoritative.
    CacheOnly = 1,

    /// Serving trial with prefetch/residency integration:
    /// may be promoted to authority after trial completion.
    ServingTrial = 2,

    /// Non-authority optimization: defrag, compaction within same
    /// receipt. Does not change authority.
    Optimization = 3,

    /// Authority-changing movement: promotion, demotion, rebake,
    /// geo catch-up. Requires full receipt-safety law.
    AuthorityMovement = 4,

    /// Necessity movement: repair, evacuation. May bypass ordinary
    /// payback and budget gates.
    Necessity = 5,
}

impl RelocationActionClass {
    /// All action classes in order.
    pub const ALL: [RelocationActionClass; 6] = [
        RelocationActionClass::None,
        RelocationActionClass::CacheOnly,
        RelocationActionClass::ServingTrial,
        RelocationActionClass::Optimization,
        RelocationActionClass::AuthorityMovement,
        RelocationActionClass::Necessity,
    ];

    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            RelocationActionClass::None => "none",
            RelocationActionClass::CacheOnly => "cache-only",
            RelocationActionClass::ServingTrial => "serving-trial",
            RelocationActionClass::Optimization => "optimization",
            RelocationActionClass::AuthorityMovement => "authority-movement",
            RelocationActionClass::Necessity => "necessity",
        }
    }

    /// Returns true when this class changes storage authority.
    #[must_use]
    pub const fn changes_authority(self) -> bool {
        matches!(
            self,
            RelocationActionClass::AuthorityMovement | RelocationActionClass::Necessity
        )
    }

    /// Returns true when this class is a droppable serving trial.
    #[must_use]
    pub const fn is_serving_trial(self) -> bool {
        matches!(
            self,
            RelocationActionClass::CacheOnly | RelocationActionClass::ServingTrial
        )
    }
}

impl core::fmt::Display for RelocationActionClass {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Heuristic input ──────────────────────────────────────────────────

/// Input snapshot for HDD, SSD, and WAN relocation heuristics.
///
/// All fields are optional; `None` means "unknown" and forces
/// conservative (blocking or low-confidence) output.
#[derive(Clone, Debug, Default)]
pub struct HeuristicInput {
    // ── Common ────────────────────────────────────────────────────
    /// Total bytes to relocate.
    pub relocation_bytes: Option<u64>,

    /// Subject was relocated within the last N milliseconds.
    pub last_relocated_ms: Option<u64>,

    /// Subject has active movement debt (bytes).
    pub movement_debt_bytes: Option<u64>,

    /// Payback window in milliseconds.
    pub payback_window_ms: Option<u64>,

    /// Predicted confidence (0-3).
    pub prediction_confidence: Option<u8>,

    /// Evidence is consistent (not contradictory).
    pub evidence_consistent: Option<bool>,

    // ── HDD-specific ──────────────────────────────────────────────
    /// Current seek distance estimate (logical blocks).
    pub hdd_seek_distance: Option<u64>,

    /// Expected seek distance after defrag (logical blocks).
    pub hdd_expected_seek_distance: Option<u64>,

    /// Current scan fragmentation ratio (0.0-1.0, higher = worse).
    pub hdd_fragmentation_ratio: Option<f64>,

    /// Expected fragmentation ratio after defrag.
    pub hdd_expected_fragmentation_ratio: Option<f64>,

    // ── SSD-specific ──────────────────────────────────────────────
    /// Current write amplification factor (ppm).
    pub ssd_write_amplification_ppm: Option<u32>,

    /// Expected write amplification after compaction (ppm).
    pub ssd_expected_write_amplification_ppm: Option<u32>,

    /// Metadata fan-out ratio (1.0 = no fan-out).
    pub ssd_metadata_fanout: Option<f64>,

    /// Placement satisfaction ratio (0.0-1.0, 1.0 = satisfied).
    pub ssd_placement_satisfaction: Option<f64>,

    /// Wear delta between hottest and coldest device (ppm).
    pub ssd_wear_delta_ppm: Option<u32>,

    /// Protected flash reserve headroom (bytes).
    pub ssd_protected_reserve_bytes: Option<u64>,
    /// Target media capability evidence is fresh.
    pub media_capability_fresh: Option<bool>,

    // ── WAN-specific ──────────────────────────────────────────────
    /// Current RPO lag (milliseconds).
    pub wan_rpo_lag_ms: Option<u64>,

    /// Available WAN bandwidth (bytes/sec).
    pub wan_bandwidth_bytes_per_sec: Option<u64>,

    /// WAN egress cost (microunits per byte).
    pub wan_egress_cost_microunits_per_byte: Option<u64>,

    /// WAN congestion window estimate (bytes).
    pub wan_congestion_window_bytes: Option<u64>,

    /// Delta transfer ratio (0.0-1.0, 0.5 = 50% bytes saved via deltas).
    pub wan_delta_ratio: Option<f64>,

    /// Compression ratio achievable (1.0 = no compression).
    pub wan_compression_ratio: Option<f64>,

    /// RPO target from policy (milliseconds).
    pub wan_rpo_target_ms: Option<u64>,
}

// ── Heuristic result ─────────────────────────────────────────────────

/// Output from a heuristic evaluation.
#[derive(Clone, Debug)]
pub struct HeuristicResult {
    /// The recommended action class.
    pub action_class: RelocationActionClass,

    /// Whether the heuristic recommends proceeding.
    pub recommend: bool,

    /// Whether the evidence was sufficient for a confident decision.
    pub evidence_sufficient: bool,

    /// Human-readable summary of the heuristic finding.
    pub summary: &'static str,

    /// Estimated payback window (milliseconds). `None` if not applicable.
    pub estimated_payback_ms: Option<u64>,

    /// Estimated wear cost (flash ppm). `None` if not applicable.
    pub estimated_wear_ppm: Option<u32>,

    /// Skip reason if the heuristic recommends against the move.
    pub skip_reason: Option<&'static str>,
}

impl HeuristicResult {
    /// Fast-reject result: blocked with a skip reason.
    #[must_use]
    pub const fn blocked(summary: &'static str, skip_reason: &'static str) -> Self {
        HeuristicResult {
            action_class: RelocationActionClass::None,
            recommend: false,
            evidence_sufficient: true,
            summary,
            estimated_payback_ms: None,
            estimated_wear_ppm: None,
            skip_reason: Some(skip_reason),
        }
    }

    /// Unknown-evidence result: cannot decide, blocks authority moves.
    #[must_use]
    pub const fn unknown(summary: &'static str) -> Self {
        HeuristicResult {
            action_class: RelocationActionClass::None,
            recommend: false,
            evidence_sufficient: false,
            summary,
            estimated_payback_ms: None,
            estimated_wear_ppm: None,
            skip_reason: Some("evidence-unknown"),
        }
    }

    /// Recommended result with the given action class.
    #[must_use]
    pub const fn recommended(
        action_class: RelocationActionClass,
        summary: &'static str,
    ) -> Self {
        HeuristicResult {
            action_class,
            recommend: true,
            evidence_sufficient: true,
            summary,
            estimated_payback_ms: None,
            estimated_wear_ppm: None,
            skip_reason: None,
        }
    }
}

impl Default for HeuristicResult {
    fn default() -> Self {
        HeuristicResult::unknown("not evaluated")
    }
}

// ── Reason → action class / confidence mapping ───────────────────────

impl GovernorRelocationReason {
    /// Minimum action class required for this relocation reason.
    #[must_use]
    pub const fn minimum_action_class(self) -> RelocationActionClass {
        match self {
            GovernorRelocationReason::PolicySatisfaction => {
                RelocationActionClass::AuthorityMovement
            }
            GovernorRelocationReason::Repair => RelocationActionClass::Necessity,
            GovernorRelocationReason::Evacuation => RelocationActionClass::Necessity,
            GovernorRelocationReason::HddDefrag => RelocationActionClass::Optimization,
            GovernorRelocationReason::SsdCompaction => RelocationActionClass::Optimization,
            GovernorRelocationReason::Rebake => RelocationActionClass::AuthorityMovement,
            GovernorRelocationReason::Promotion => RelocationActionClass::AuthorityMovement,
            GovernorRelocationReason::Demotion => RelocationActionClass::AuthorityMovement,
            GovernorRelocationReason::GeoCatchup => RelocationActionClass::AuthorityMovement,
            GovernorRelocationReason::WearRebalance => RelocationActionClass::Optimization,
        }
    }

    /// Minimum prediction confidence level required (0-3).
    #[must_use]
    pub const fn minimum_prediction_confidence(self) -> u8 {
        match self {
            GovernorRelocationReason::Repair => 0,
            GovernorRelocationReason::Evacuation => 0,
            GovernorRelocationReason::HddDefrag => 1, // Low
            GovernorRelocationReason::SsdCompaction => 1, // Low
            GovernorRelocationReason::WearRebalance => 2, // Medium
            GovernorRelocationReason::PolicySatisfaction => 2, // Medium
            GovernorRelocationReason::Rebake => 2, // Medium
            GovernorRelocationReason::Promotion => 2, // Medium
            GovernorRelocationReason::Demotion => 2, // Medium
            GovernorRelocationReason::GeoCatchup => 2, // Medium
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_class_labels_nonempty() {
        for ac in &RelocationActionClass::ALL {
            assert!(!format!("{ac}").is_empty());
        }
    }

    #[test]
    fn action_class_ordering() {
        assert!(RelocationActionClass::None < RelocationActionClass::CacheOnly);
        assert!(RelocationActionClass::CacheOnly < RelocationActionClass::ServingTrial);
        assert!(RelocationActionClass::ServingTrial < RelocationActionClass::Optimization);
        assert!(
            RelocationActionClass::Optimization < RelocationActionClass::AuthorityMovement
        );
        assert!(
            RelocationActionClass::AuthorityMovement < RelocationActionClass::Necessity
        );
    }

    #[test]
    fn necessity_reasons_map_to_necessity_action_class() {
        assert_eq!(
            GovernorRelocationReason::Repair.minimum_action_class(),
            RelocationActionClass::Necessity
        );
        assert_eq!(
            GovernorRelocationReason::Evacuation.minimum_action_class(),
            RelocationActionClass::Necessity
        );
    }

    #[test]
    fn optimization_reasons_map_to_optimization_action_class() {
        assert_eq!(
            GovernorRelocationReason::HddDefrag.minimum_action_class(),
            RelocationActionClass::Optimization
        );
        assert_eq!(
            GovernorRelocationReason::SsdCompaction.minimum_action_class(),
            RelocationActionClass::Optimization
        );
    }

    #[test]
    fn authority_reasons_map_to_authority_movement() {
        for reason in &[
            GovernorRelocationReason::Promotion,
            GovernorRelocationReason::Demotion,
            GovernorRelocationReason::Rebake,
            GovernorRelocationReason::GeoCatchup,
            GovernorRelocationReason::PolicySatisfaction,
        ] {
            assert_eq!(
                reason.minimum_action_class(),
                RelocationActionClass::AuthorityMovement,
                "{reason} should require AuthorityMovement"
            );
        }
    }

    #[test]
    fn repair_has_zero_min_confidence() {
        assert_eq!(GovernorRelocationReason::Repair.minimum_prediction_confidence(), 0);
    }

    #[test]
    fn authority_moves_require_medium_confidence() {
        for reason in &[
            GovernorRelocationReason::Promotion,
            GovernorRelocationReason::Demotion,
            GovernorRelocationReason::Rebake,
            GovernorRelocationReason::GeoCatchup,
        ] {
            assert_eq!(
                reason.minimum_prediction_confidence(),
                2,
                "{reason} should require medium confidence (2)"
            );
        }
    }

    #[test]
    fn heuristic_result_blocked() {
        let r = HeuristicResult::blocked("test summary", "test-skip");
        assert!(!r.recommend);
        assert_eq!(r.action_class, RelocationActionClass::None);
        assert_eq!(r.skip_reason, Some("test-skip"));
        assert!(r.evidence_sufficient);
    }

    #[test]
    fn heuristic_result_unknown() {
        let r = HeuristicResult::unknown("test unknown");
        assert!(!r.recommend);
        assert!(!r.evidence_sufficient);
    }

    #[test]
    fn heuristic_result_recommended() {
        let r = HeuristicResult::recommended(
            RelocationActionClass::AuthorityMovement,
            "test recommended",
        );
        assert!(r.recommend);
        assert_eq!(r.action_class, RelocationActionClass::AuthorityMovement);
    }
}
