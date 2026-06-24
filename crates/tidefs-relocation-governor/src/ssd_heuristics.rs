// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! SSD/NVMe-specific relocation heuristics.
//!
//! Flash relocation must require write-amplification, metadata fan-out,
//! placement-satisfaction, wear-rebalance, or proven payback benefit
//! before spending flash lifetime. Every SSD compaction or wear-rebalance
//! move must cite WAF reduction, protected-reserve headroom, and media
//! capability evidence.

use crate::heuristics::{HeuristicInput, HeuristicResult, RelocationActionClass};

/// Minimum write-amplification reduction (ppm) to justify compaction.
const MIN_WAF_REDUCTION_PPM: u32 = 50;

/// Minimum metadata fan-out improvement ratio.
const MIN_FANOUT_IMPROVEMENT: f64 = 0.10;

/// Minimum placement-satisfaction improvement ratio.
const MIN_PLACEMENT_IMPROVEMENT: f64 = 0.05;

/// Wear delta threshold for wear-rebalance (ppm). Below this, rebalance
/// is not justified.
const MIN_WEAR_DELTA_FOR_REBALANCE_PPM: u32 = 1000;

/// Minimum protected reserve headroom ratio (relative to relocation bytes).
const MIN_PROTECTED_RESERVE_RATIO: f64 = 2.0;

/// SSD compaction heuristic.
///
/// Evaluates whether SSD compaction (segment drain, reclaim-debt reduction)
/// is justified by WAF reduction, metadata fan-out improvement, or
/// placement-satisfaction improvement.
#[must_use]
pub fn evaluate_ssd_compaction(input: &HeuristicInput) -> HeuristicResult {
    // Require media capability evidence (implicitly checked by hard gates).
    // Here we verify the heuristic-specific inputs.

    let waf_current = match input.ssd_write_amplification_ppm {
        Some(w) => w,
        None => return HeuristicResult::unknown("ssd-write-amplification-unknown"),
    };
    let waf_expected = match input.ssd_expected_write_amplification_ppm {
        Some(w) => w,
        None => return HeuristicResult::unknown("ssd-expected-write-amplification-unknown"),
    };

    // Compute improvements
    let waf_reduction = waf_current.saturating_sub(waf_expected);
    let fanout_current = input.ssd_metadata_fanout.unwrap_or(1.0);
    let fanout_improvement = if fanout_current > 1.0 {
        fanout_current - 1.0
    } else {
        0.0
    };
    let placement_current = input.ssd_placement_satisfaction.unwrap_or(1.0);
    let placement_goal = 1.0;
    let placement_deficit = placement_goal - placement_current;
    let placement_improvement = if placement_deficit > 0.0 && placement_current < 1.0 {
        placement_deficit
    } else {
        0.0
    };

    // At least one improvement must meet threshold.
    let waf_ok = waf_reduction >= MIN_WAF_REDUCTION_PPM;
    let fanout_ok = fanout_improvement >= MIN_FANOUT_IMPROVEMENT;
    let placement_ok = placement_improvement >= MIN_PLACEMENT_IMPROVEMENT;

    if !waf_ok && !fanout_ok && !placement_ok {
        return HeuristicResult::blocked(
            "ssd-compaction-no-measurable-benefit",
            "no-waf-fanout-or-placement-improvement",
        );
    }

    // Check protected reserve headroom.
    if let Some(reloc_bytes) = input.relocation_bytes {
        if let Some(reserve_bytes) = input.ssd_protected_reserve_bytes {
            let reserve_ratio = reserve_bytes as f64 / reloc_bytes as f64;
            if reserve_ratio < MIN_PROTECTED_RESERVE_RATIO {
                return HeuristicResult::blocked(
                    "ssd-compaction-protected-reserve-insufficient",
                    "protected-reserve-too-low",
                );
            }
        }
    }

    // Anti-thrash: if recently relocated, block
    if let Some(last_ms) = input.last_relocated_ms {
        if last_ms < 60_000 {
            return HeuristicResult::blocked(
                "ssd-compaction-too-soon-after-relocation",
                "movement-debt-active",
            );
        }
    }

    // Estimate wear cost
    let relocation_bytes = input.relocation_bytes.unwrap_or(0);
    let wear_ppm = if relocation_bytes > 0 {
        // Rough: WAF * relocation writes cost. In practice this comes from
        // #844 cost/wear snapshots. For now we use the current WAF as cost.
        Some(waf_current)
    } else {
        None
    };

    let mut result = HeuristicResult::recommended(
        RelocationActionClass::Optimization,
        "ssd-compaction-justified",
    );
    result.estimated_wear_ppm = wear_ppm;
    result
}

/// SSD wear-rebalance heuristic.
///
/// Evaluates whether wear-rebalance movement is justified by wear delta
/// across devices.
#[must_use]
pub fn evaluate_ssd_wear_rebalance(input: &HeuristicInput) -> HeuristicResult {
    let wear_delta = match input.ssd_wear_delta_ppm {
        Some(d) => d,
        None => return HeuristicResult::unknown("ssd-wear-delta-unknown"),
    };

    if wear_delta < MIN_WEAR_DELTA_FOR_REBALANCE_PPM {
        return HeuristicResult::blocked(
            "ssd-wear-rebalance-not-justified-delta-too-small",
            "wear-delta-below-threshold",
        );
    }

    // Check protected reserve
    if let Some(reloc_bytes) = input.relocation_bytes {
        if let Some(reserve_bytes) = input.ssd_protected_reserve_bytes {
            let reserve_ratio = reserve_bytes as f64 / reloc_bytes as f64;
            if reserve_ratio < MIN_PROTECTED_RESERVE_RATIO {
                return HeuristicResult::blocked(
                    "ssd-wear-rebalance-protected-reserve-insufficient",
                    "protected-reserve-too-low",
                );
            }
        }
    }

    // Anti-thrash
    if let Some(last_ms) = input.last_relocated_ms {
        if last_ms < 120_000 {
            return HeuristicResult::blocked(
                "ssd-wear-rebalance-too-soon-after-relocation",
                "movement-debt-active",
            );
        }
    }

    let mut result = HeuristicResult::recommended(
        RelocationActionClass::Optimization,
        "ssd-wear-rebalance-justified",
    );
    result.estimated_wear_ppm = input.ssd_write_amplification_ppm;
    result
}

/// General SSD relocation eligibility check.
///
/// Returns true when evidence is sufficient to evaluate SSD relocation.
/// For the first #848 law/model slice, missing evidence produces
/// blocked/refused state.
#[must_use]
pub fn ssd_relocation_eligibility(input: &HeuristicInput) -> HeuristicResult {
    // All SSD moves require WAF evidence and protected reserve evidence.
    if input.ssd_write_amplification_ppm.is_none() {
        return HeuristicResult::unknown("ssd-waf-evidence-missing");
    }
    if input.ssd_protected_reserve_bytes.is_none() {
        return HeuristicResult::unknown("ssd-protected-reserve-evidence-missing");
    }
    if input.media_capability_fresh == Some(false) {
        return HeuristicResult::blocked(
            "ssd-media-capability-stale",
            "media-capability-evidence-stale",
        );
    }
    HeuristicResult::recommended(RelocationActionClass::Optimization, "ssd-eligible")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssd_compaction_input() -> HeuristicInput {
        HeuristicInput {
            ssd_write_amplification_ppm: Some(200),
            ssd_expected_write_amplification_ppm: Some(100),
            ssd_metadata_fanout: Some(1.5),
            ssd_placement_satisfaction: Some(0.85),
            relocation_bytes: Some(1024 * 1024),
            ssd_protected_reserve_bytes: Some(10 * 1024 * 1024),
            ..HeuristicInput::default()
        }
    }

    #[test]
    fn recommends_compaction_with_waf_reduction() {
        let input = ssd_compaction_input();
        let result = evaluate_ssd_compaction(&input);
        assert!(result.recommend);
        assert_eq!(result.action_class, RelocationActionClass::Optimization);
    }

    #[test]
    fn refuses_compaction_with_no_improvement() {
        let mut input = ssd_compaction_input();
        input.ssd_expected_write_amplification_ppm = Some(190); // only 10ppm reduction
        input.ssd_metadata_fanout = Some(1.01);
        input.ssd_placement_satisfaction = Some(0.98);
        let result = evaluate_ssd_compaction(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_compaction_when_protected_reserve_too_low() {
        let mut input = ssd_compaction_input();
        input.ssd_protected_reserve_bytes = Some(1024 * 1024); // 1:1 ratio, below 2:1
        let result = evaluate_ssd_compaction(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_compaction_when_recently_relocated() {
        let mut input = ssd_compaction_input();
        input.last_relocated_ms = Some(10_000);
        let result = evaluate_ssd_compaction(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_wear_rebalance_when_delta_too_small() {
        let mut input = ssd_compaction_input();
        input.ssd_wear_delta_ppm = Some(500); // below 1000 threshold
        let result = evaluate_ssd_wear_rebalance(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn recommends_wear_rebalance_with_large_delta() {
        let mut input = ssd_compaction_input();
        input.ssd_wear_delta_ppm = Some(5000);
        let result = evaluate_ssd_wear_rebalance(&input);
        assert!(result.recommend);
    }

    #[test]
    fn unknown_waf_produces_unknown() {
        let input = HeuristicInput::default();
        let result = evaluate_ssd_compaction(&input);
        assert!(!result.recommend);
        assert!(!result.evidence_sufficient);
    }

    #[test]
    fn ssd_eligibility_stale_media_capability_blocked() {
        let mut input = ssd_compaction_input();
        input.media_capability_fresh = Some(false);
        let result = ssd_relocation_eligibility(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn ssd_eligibility_missing_waf_unknown() {
        let input = HeuristicInput::default();
        let result = ssd_relocation_eligibility(&input);
        assert!(!result.evidence_sufficient);
    }
}
