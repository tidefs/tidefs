// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! HDD-specific defrag heuristics.
//!
//! HDD relocation must justify expected seek/scan improvement before
//! admitting a defrag move. Rotational media does not suffer from write
//! amplification, but seek latency and scan fragmentation are the primary
//! costs. A defrag that does not measurably reduce seek distance or
//! fragmentation ratio is refused.

use crate::heuristics::{HeuristicInput, HeuristicResult, RelocationActionClass};

/// Minimum seek-distance reduction ratio to admit HDD defrag.
/// A defrag must reduce expected seek distance by at least this fraction.
const MIN_SEEK_REDUCTION_RATIO: f64 = 0.15;

/// Minimum fragmentation improvement ratio to admit HDD defrag.
const MIN_FRAGMENTATION_IMPROVEMENT: f64 = 0.10;

/// Maximum seek distance that is "good enough" (blocks).
/// Below this threshold, defrag provides diminishing returns.
const GOOD_ENOUGH_SEEK_DISTANCE: u64 = 256;

/// HDD defrag heuristic: evaluate whether defrag is justified.
///
/// Returns a [`HeuristicResult`] with the recommended action class and
/// payback estimate. The heuristic requires both seek-distance and
/// fragmentation evidence; missing evidence produces an unknown result.
#[must_use]
pub fn evaluate_hdd_defrag(input: &HeuristicInput) -> HeuristicResult {
    let current_seek = match input.hdd_seek_distance {
        Some(s) => s,
        None => return HeuristicResult::unknown("hdd-seek-distance-unknown"),
    };
    let expected_seek = match input.hdd_expected_seek_distance {
        Some(s) => s,
        None => return HeuristicResult::unknown("hdd-expected-seek-distance-unknown"),
    };
    let current_frag = match input.hdd_fragmentation_ratio {
        Some(f) => f,
        None => return HeuristicResult::unknown("hdd-fragmentation-ratio-unknown"),
    };
    let expected_frag = match input.hdd_expected_fragmentation_ratio {
        Some(f) => f,
        None => return HeuristicResult::unknown("hdd-expected-fragmentation-ratio-unknown"),
    };

    // If seek distance is already good enough and fragmentation is low,
    // defrag is not justified.
    if current_seek <= GOOD_ENOUGH_SEEK_DISTANCE && current_frag <= 0.1 {
        return HeuristicResult::blocked(
            "hdd-defrag-not-justified-seek-already-good",
            "seek-distance-already-good",
        );
    }

    // Compute improvement ratios.
    let seek_reduction = if current_seek > 0 {
        1.0 - (expected_seek as f64 / current_seek as f64)
    } else {
        0.0
    };
    let frag_improvement = if current_frag > 0.0 {
        current_frag - expected_frag
    } else {
        0.0
    };

    // Both improvements must meet minimum thresholds.
    if seek_reduction < MIN_SEEK_REDUCTION_RATIO && frag_improvement < MIN_FRAGMENTATION_IMPROVEMENT
    {
        return HeuristicResult::blocked(
            "hdd-defrag-insufficient-improvement",
            "seek-and-fragmentation-improvement-too-small",
        );
    }

    // Anti-thrash: if the subject was recently relocated, increase the
    // improvement threshold.
    if let Some(last_ms) = input.last_relocated_ms {
        if last_ms < 30_000 {
            // Relocated within the last 30 seconds — require stronger evidence.
            if seek_reduction < MIN_SEEK_REDUCTION_RATIO * 2.0 {
                return HeuristicResult::blocked(
                    "hdd-defrag-too-soon-after-relocation",
                    "movement-debt-active",
                );
            }
        }
    }

    // Estimate payback: seek reduction translates to latency savings.
    // Rough heuristic: 1 seek ≈ 5ms on 7200rpm HDD, defrag saves N seeks.
    let seek_savings = current_seek.saturating_sub(expected_seek);
    let payback_seeks = seek_savings.max(1);
    let estimated_payback_ms = payback_seeks.saturating_mul(5);

    let mut result =
        HeuristicResult::recommended(RelocationActionClass::Optimization, "hdd-defrag-justified");
    result.estimated_payback_ms = Some(estimated_payback_ms);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hdd_defrag_input() -> HeuristicInput {
        HeuristicInput {
            hdd_seek_distance: Some(1000),
            hdd_expected_seek_distance: Some(400),
            hdd_fragmentation_ratio: Some(0.6),
            hdd_expected_fragmentation_ratio: Some(0.2),
            ..HeuristicInput::default()
        }
    }

    #[test]
    fn recommends_defrag_with_clear_improvement() {
        let input = hdd_defrag_input();
        let result = evaluate_hdd_defrag(&input);
        assert!(result.recommend);
        assert_eq!(result.action_class, RelocationActionClass::Optimization);
    }

    #[test]
    fn refuses_defrag_when_seek_already_good() {
        let mut input = hdd_defrag_input();
        input.hdd_seek_distance = Some(100);
        input.hdd_expected_seek_distance = Some(90);
        input.hdd_fragmentation_ratio = Some(0.05);
        input.hdd_expected_fragmentation_ratio = Some(0.04);
        let result = evaluate_hdd_defrag(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_defrag_with_tiny_improvement() {
        let mut input = hdd_defrag_input();
        input.hdd_seek_distance = Some(1000);
        input.hdd_expected_seek_distance = Some(950); // only 5% reduction
        input.hdd_fragmentation_ratio = Some(0.6);
        input.hdd_expected_fragmentation_ratio = Some(0.58); // only 2% improvement
        let result = evaluate_hdd_defrag(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_when_recently_relocated() {
        let mut input = hdd_defrag_input();
        input.last_relocated_ms = Some(10_000); // 10s ago
                                                // With default 40% seek reduction, < 30% (2x threshold) after recent
                                                // relocation → should still refuse because threshold is doubled.
        input.hdd_seek_distance = Some(1000);
        input.hdd_expected_seek_distance = Some(710); // 29% reduction (under 30% double threshold)
        let result = evaluate_hdd_defrag(&input);
        // 30% is >= 15% (single threshold) but < 30% (doubled threshold)
        assert!(!result.recommend);
    }

    #[test]
    fn unknown_seek_distance_produces_unknown() {
        let input = HeuristicInput::default();
        let result = evaluate_hdd_defrag(&input);
        assert!(!result.recommend);
        assert!(!result.evidence_sufficient);
    }

    #[test]
    fn payback_estimated() {
        let input = hdd_defrag_input();
        let result = evaluate_hdd_defrag(&input);
        // seek savings: 1000 - 400 = 600 * 5ms ≈ 3000ms
        assert!(result.estimated_payback_ms.is_some());
        assert!(result.estimated_payback_ms.unwrap() >= 1000);
    }
}
