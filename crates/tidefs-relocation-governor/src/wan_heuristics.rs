// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! WAN/internet relocation heuristic for geo catch-up.
//!
//! Geo catch-up relocation must include batching, compression, delta
//! transfer, congestion/cost awareness, and explicit RPO lag receipts.
//! No RDMA assumption is made; the heuristic must work over commodity
//! WAN links with variable bandwidth and egress costs.

use crate::heuristics::{HeuristicInput, HeuristicResult, RelocationActionClass};

/// Maximum RPO lag ratio (current / target) before catch-up is required.
/// Above this ratio, catch-up is urgent.
const RPO_CATCHUP_URGENCY_RATIO: f64 = 2.0;

/// Minimum delta transfer ratio to make delta transfer worthwhile.
const MIN_DELTA_RATIO: f64 = 0.3;

/// Minimum compression ratio to make compression worthwhile.
const MIN_COMPRESSION_RATIO: f64 = 0.7;

/// Minimum bandwidth (bytes/sec) to attempt catch-up.
const MIN_CATCHUP_BANDWIDTH_BPS: u64 = 1024 * 1024; // 1 MiB/s

/// Geo catch-up heuristic.
///
/// Evaluates whether WAN/internet geo catch-up is feasible and cost-effective.
/// The heuristic considers RPO lag, bandwidth, egress cost, delta transfer
/// potential, compression opportunity, and congestion.
#[must_use]
pub fn evaluate_geo_catchup(input: &HeuristicInput) -> HeuristicResult {
    let rpo_lag_ms = match input.wan_rpo_lag_ms {
        Some(l) => l,
        None => return HeuristicResult::unknown("wan-rpo-lag-unknown"),
    };
    let rpo_target_ms = match input.wan_rpo_target_ms {
        Some(t) => t,
        None => return HeuristicResult::unknown("wan-rpo-target-unknown"),
    };

    // RPO lag must exceed target for catch-up to be meaningful.
    if rpo_lag_ms <= rpo_target_ms {
        return HeuristicResult::blocked(
            "geo-catchup-not-needed-rpo-within-target",
            "rpo-lag-within-target",
        );
    }

    // Urgency classification
    let urgency = rpo_lag_ms as f64 / rpo_target_ms as f64;
    let is_urgent = urgency >= RPO_CATCHUP_URGENCY_RATIO;

    // Bandwidth check
    let bandwidth = match input.wan_bandwidth_bytes_per_sec {
        Some(b) => b,
        None => return HeuristicResult::unknown("wan-bandwidth-unknown"),
    };
    if bandwidth < MIN_CATCHUP_BANDWIDTH_BPS && !is_urgent {
        return HeuristicResult::blocked(
            "geo-catchup-bandwidth-insufficient",
            "bandwidth-below-minimum",
        );
    }

    // Egress cost check
    if let Some(cost_per_byte) = input.wan_egress_cost_microunits_per_byte {
        if let Some(reloc_bytes) = input.relocation_bytes {
            let total_cost = cost_per_byte.saturating_mul(reloc_bytes);
            // If total egress cost exceeds a reasonable threshold (1M microunits),
            // require urgent catch-up or explicit operator override.
            if total_cost > 1_000_000 && !is_urgent {
                return HeuristicResult::blocked(
                    "geo-catchup-egress-cost-too-high",
                    "egress-cost-exceeds-threshold",
                );
            }
        }
    }

    // Congestion check
    if let Some(cwnd) = input.wan_congestion_window_bytes {
        if cwnd < 65536 && !is_urgent {
            return HeuristicResult::blocked(
                "geo-catchup-congested",
                "congestion-window-too-small",
            );
        }
    }

    // Determine transfer strategy
    let use_delta = input.wan_delta_ratio.unwrap_or(0.0) >= MIN_DELTA_RATIO;
    let use_compression = input.wan_compression_ratio.unwrap_or(1.0) <= MIN_COMPRESSION_RATIO;

    // Estimate time to catch up
    let effective_bandwidth = if use_compression {
        (bandwidth as f64 / input.wan_compression_ratio.unwrap_or(1.0)) as u64
    } else {
        bandwidth
    };
    let transfer_bytes = if use_delta {
        let delta_ratio = input.wan_delta_ratio.unwrap_or(1.0);
        (input.relocation_bytes.unwrap_or(0) as f64 * delta_ratio) as u64
    } else {
        input.relocation_bytes.unwrap_or(0)
    };

    let estimated_catchup_ms = if effective_bandwidth > 0 {
        (transfer_bytes as f64 / effective_bandwidth as f64 * 1000.0) as u64
    } else {
        u64::MAX
    };

    let action_class = if is_urgent {
        RelocationActionClass::Necessity
    } else {
        RelocationActionClass::AuthorityMovement
    };

    let summary = if use_delta && use_compression {
        "geo-catchup-justified-delta-compressed"
    } else if use_delta {
        "geo-catchup-justified-delta"
    } else if use_compression {
        "geo-catchup-justified-compressed"
    } else {
        "geo-catchup-justified-full-transfer"
    };

    let mut result = HeuristicResult::recommended(action_class, summary);
    result.estimated_payback_ms = Some(estimated_catchup_ms);

    result
}

/// Geo catch-up batching estimate.
///
/// Returns the recommended batch size in bytes for a WAN transfer,
/// considering bandwidth, RPO window, and congestion.
#[must_use]
pub fn geo_catchup_batch_size_bytes(input: &HeuristicInput) -> Option<u64> {
    let bandwidth = input.wan_bandwidth_bytes_per_sec?;
    let rpo_target_ms = input.wan_rpo_target_ms?;

    // Batch should complete within 10% of the RPO target window.
    let max_batch_time_ms = rpo_target_ms / 10;
    let max_batch_bytes = bandwidth.saturating_mul(max_batch_time_ms) / 1000;

    // Cap at congestion window if available.
    if let Some(cwnd) = input.wan_congestion_window_bytes {
        Some(max_batch_bytes.min(cwnd))
    } else {
        Some(max_batch_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geo_catchup_input() -> HeuristicInput {
        HeuristicInput {
            wan_rpo_lag_ms: Some(30_000),                        // 30s lag
            wan_rpo_target_ms: Some(10_000),                     // 10s target
            wan_bandwidth_bytes_per_sec: Some(10 * 1024 * 1024), // 10 MiB/s
            wan_egress_cost_microunits_per_byte: Some(1),
            wan_congestion_window_bytes: Some(1024 * 1024),
            wan_delta_ratio: Some(0.5),
            wan_compression_ratio: Some(0.5),
            relocation_bytes: Some(100 * 1024 * 1024), // 100 MiB
            ..HeuristicInput::default()
        }
    }

    #[test]
    fn recommends_catchup_with_lag_exceeding_target() {
        let input = geo_catchup_input();
        let result = evaluate_geo_catchup(&input);
        assert!(result.recommend);
        assert_eq!(result.action_class, RelocationActionClass::Necessity);
    }

    #[test]
    fn urgent_catchup_when_lag_far_exceeds_target() {
        let mut input = geo_catchup_input();
        input.wan_rpo_lag_ms = Some(50_000); // 5x target → urgent
        let result = evaluate_geo_catchup(&input);
        assert!(result.recommend);
        assert_eq!(result.action_class, RelocationActionClass::Necessity);
    }

    #[test]
    fn refuses_catchup_when_rpo_within_target() {
        let mut input = geo_catchup_input();
        input.wan_rpo_lag_ms = Some(5_000); // within target
        let result = evaluate_geo_catchup(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_catchup_when_bandwidth_too_low() {
        let mut input = geo_catchup_input();
        input.wan_bandwidth_bytes_per_sec = Some(512 * 1024); // 512 KiB/s
        input.wan_rpo_lag_ms = Some(15_000); // non-urgent (1.5x target)
        let result = evaluate_geo_catchup(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn refuses_catchup_when_egress_cost_too_high() {
        let mut input = geo_catchup_input();
        input.wan_egress_cost_microunits_per_byte = Some(100);
        input.relocation_bytes = Some(100 * 1024 * 1024); // 100 MiB * 100 = 10B microunits
        input.wan_rpo_lag_ms = Some(15_000); // non-urgent (1.5x target)
        let result = evaluate_geo_catchup(&input);
        assert!(!result.recommend);
    }

    #[test]
    fn unknown_rpo_lag_produces_unknown() {
        let input = HeuristicInput::default();
        let result = evaluate_geo_catchup(&input);
        assert!(!result.recommend);
        assert!(!result.evidence_sufficient);
    }

    #[test]
    fn batch_size_scales_with_bandwidth() {
        let input = geo_catchup_input();
        let batch = geo_catchup_batch_size_bytes(&input).unwrap();
        // 10 MiB/s * (10s/10) / 1000 = 10 MiB/s * 1s = 10 MiB, capped at cwnd 1 MiB
        assert!(batch > 0);
        assert!(batch <= 1024 * 1024); // capped at cwnd
    }

    #[test]
    fn batch_size_none_when_missing_inputs() {
        let input = HeuristicInput::default();
        assert!(geo_catchup_batch_size_bytes(&input).is_none());
    }
}
