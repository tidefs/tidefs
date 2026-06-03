//! Multi-node performance degradation budget: compares single-node baseline
//! KPIs against multi-node measurements and evaluates whether the overhead
//! stays within the approved degradation budget.
//!
//! Validation tier: Tier 7 multi-process distributed/RDMA runtime (target).

use super::gate_entry::{BudgetBucket, BudgetDecision, MeasuredKpi, MultiNodeDegradationBudget};

/// Result of a degradation budget comparison between single-node and
/// multi-node measurements.
#[derive(Debug, Clone)]
pub struct DegradationComparison {
    /// Single-node baseline KPIs (from deterministic harness or single-node runtime).
    pub single_node_kpis: Vec<MeasuredKpi>,
    /// Multi-node measured KPIs (from multi-process distributed runtime).
    pub multi_node_kpis: Vec<MeasuredKpi>,
    /// The degradation budget applied.
    pub budget: MultiNodeDegradationBudget,
    /// Per-KPI bucket violations.
    pub buckets: Vec<BudgetBucket>,
    /// Overall decision.
    pub decision: BudgetDecision,
}

impl DegradationComparison {
    /// Evaluate multi-node KPIs against the single-node baseline using the
    /// given degradation budget. If multi-node KPIs are empty (no runtime
    /// validation), the decision is Refuse.
    pub fn evaluate(
        single_node_kpis: Vec<MeasuredKpi>,
        multi_node_kpis: Vec<MeasuredKpi>,
        budget: MultiNodeDegradationBudget,
    ) -> Self {
        if multi_node_kpis.is_empty() {
            return Self {
                single_node_kpis,
                multi_node_kpis,
                budget,
                buckets: vec![BudgetBucket::MissingArtifact],
                decision: BudgetDecision::Refuse,
            };
        }

        let mut buckets = Vec::new();

        // Compare each multi-node KPI against its single-node counterpart.
        for mn_kpi in &multi_node_kpis {
            let sn_kpi = single_node_kpis.iter().find(|k| k.name == mn_kpi.name);

            if let Some(sn) = sn_kpi {
                // Throughput comparison: multi-node / single-node >= min_throughput_ratio
                if (mn_kpi.name.contains("throughput") || mn_kpi.unit.contains("MB/s"))
                    && sn.value > 0.0
                {
                    let ratio = mn_kpi.value / sn.value;
                    if ratio < budget.min_throughput_ratio {
                        buckets.push(BudgetBucket::ThroughputRegression);
                    }
                }

                // Latency comparison: multi-node / single-node <= max_latency_overhead_ratio
                if (mn_kpi.name.contains("latency") || mn_kpi.unit.contains("us")) && sn.value > 0.0
                {
                    let ratio = mn_kpi.value / sn.value;
                    if ratio > budget.max_latency_overhead_ratio {
                        buckets.push(BudgetBucket::LatencyRegression);
                    }
                }
            } else {
                // Multi-node KPI has no single-node counterpart — can't compare.
                buckets.push(BudgetBucket::NoComparator);
            }
        }

        let decision = if buckets.iter().any(|b| b.is_release_blocking()) {
            BudgetDecision::Fail
        } else {
            BudgetDecision::Pass
        };

        Self {
            single_node_kpis,
            multi_node_kpis,
            budget,
            buckets,
            decision,
        }
    }

    /// Convenience: create a refused comparison (no multi-node runtime validation).
    pub fn refused(single_node_kpis: Vec<MeasuredKpi>) -> Self {
        Self {
            single_node_kpis,
            multi_node_kpis: Vec::new(),
            budget: MultiNodeDegradationBudget::release_standard(),
            buckets: vec![BudgetBucket::MissingArtifact],
            decision: BudgetDecision::Refuse,
        }
    }

    /// Whether the degradation budget is satisfied.
    pub fn passed(&self) -> bool {
        self.decision == BudgetDecision::Pass
    }

    /// Summary line suitable for log/validation output.
    pub fn summary_line(&self) -> String {
        format!(
            "degradation-budget: decision={:?} buckets={:?} sn_kpis={} mn_kpis={}",
            self.decision,
            self.buckets,
            self.single_node_kpis.len(),
            self.multi_node_kpis.len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kpi(name: &str, value: f64, unit: &str) -> MeasuredKpi {
        MeasuredKpi {
            ref_id: format!("kpi.{name}"),
            name: name.into(),
            value,
            unit: unit.into(),
            passed: None,
            percentile: None,
        }
    }

    #[test]
    fn empty_multi_node_is_refused() {
        let sn = vec![kpi("latency_p99_us", 500.0, "us")];
        let cmp = DegradationComparison::evaluate(
            sn,
            vec![],
            MultiNodeDegradationBudget::release_standard(),
        );
        assert_eq!(cmp.decision, BudgetDecision::Refuse);
        assert!(cmp.buckets.contains(&BudgetBucket::MissingArtifact));
    }

    #[test]
    fn acceptable_latency_overhead_passes() {
        let sn = vec![kpi("latency_p99_us", 500.0, "us")];
        let mn = vec![kpi("latency_p99_us", 900.0, "us")]; // 1.8x <= 2.0x
        let cmp =
            DegradationComparison::evaluate(sn, mn, MultiNodeDegradationBudget::release_standard());
        assert_eq!(cmp.decision, BudgetDecision::Pass);
    }

    #[test]
    fn excessive_latency_overhead_fails() {
        let sn = vec![kpi("latency_p99_us", 500.0, "us")];
        let mn = vec![kpi("latency_p99_us", 1500.0, "us")]; // 3.0x > 2.0x
        let cmp =
            DegradationComparison::evaluate(sn, mn, MultiNodeDegradationBudget::release_standard());
        assert_eq!(cmp.decision, BudgetDecision::Fail);
        assert!(cmp.buckets.contains(&BudgetBucket::LatencyRegression));
    }

    #[test]
    fn acceptable_throughput_ratio_passes() {
        let sn = vec![kpi("throughput_mb_s", 100.0, "MB/s")];
        let mn = vec![kpi("throughput_mb_s", 60.0, "MB/s")]; // 0.6x >= 0.5x
        let cmp =
            DegradationComparison::evaluate(sn, mn, MultiNodeDegradationBudget::release_standard());
        assert_eq!(cmp.decision, BudgetDecision::Pass);
    }

    #[test]
    fn insufficient_throughput_ratio_fails() {
        let sn = vec![kpi("throughput_mb_s", 100.0, "MB/s")];
        let mn = vec![kpi("throughput_mb_s", 40.0, "MB/s")]; // 0.4x < 0.5x
        let cmp =
            DegradationComparison::evaluate(sn, mn, MultiNodeDegradationBudget::release_standard());
        assert_eq!(cmp.decision, BudgetDecision::Fail);
        assert!(cmp.buckets.contains(&BudgetBucket::ThroughputRegression));
    }

    #[test]
    fn missing_comparator_adds_bucket() {
        let sn = vec![kpi("throughput_mb_s", 100.0, "MB/s")];
        let mn = vec![kpi("iops", 5000.0, "ops/s")]; // no single-node counterpart
        let cmp =
            DegradationComparison::evaluate(sn, mn, MultiNodeDegradationBudget::release_standard());
        // NoComparator is not release-blocking, so should still pass
        assert_eq!(cmp.decision, BudgetDecision::Pass);
        assert!(cmp.buckets.contains(&BudgetBucket::NoComparator));
    }
}
