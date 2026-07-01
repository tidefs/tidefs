// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::validation_tier::ValidationTier;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadEnvelope {
    pub ref_id: String,
    pub description: String,
    pub op_mix: OpMix,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpMix {
    pub read_pct: u8,
    pub write_pct: u8,
    pub metadata_pct: u8,
    pub sync_pct: u8,
    pub concurrency: u32,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvironmentManifest {
    pub profile_ref: String,
    pub host_class: String,
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub kernel_version: String,
    pub storage_backend: String,
    pub cache_mode: String,
    pub feature_flags: Vec<String>,
    pub background_load: Option<String>,
    pub noise_policy: NoisePolicy,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NoisePolicy {
    pub ref_id: String,
    pub warmup_samples: u32,
    pub min_samples: u32,
    pub max_cv: f64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetClass {
    pub ref_id: String,
    pub kpi_family: String,
    pub floor_description: String,
    pub release_blocking: bool,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetDecision {
    Pass,
    Fail,
    Refuse,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparatorRef {
    pub ref_id: String,
    pub commit_sha: Option<String>,
    pub description: String,
    pub baseline_kpis: Vec<BaselineKpi>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BaselineKpi {
    pub name: String,
    pub value: f64,
    pub unit: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RowStatus {
    Pass,
    Fail,
    Refuse,
    Pending,
}
/// Absolute numeric budget thresholds per row.
/// Derived from the source-backed performance budget matrix classes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NumericBudget {
    /// Minimum throughput floor in MiB/s. 0.0 means not enforced.
    pub throughput_floor_mb_s: f64,
    /// Maximum p95 latency ceiling in microseconds. 0.0 means not enforced.
    pub latency_p95_ceiling_us: f64,
    /// Maximum p99 latency ceiling in microseconds. 0.0 means not enforced.
    pub latency_p99_ceiling_us: f64,
    /// Minimum IOPS floor. 0 means not enforced.
    pub iops_floor: u64,
    /// Reference to the budget class this was derived from.
    pub budget_class_ref: String,
}

impl NumericBudget {
    /// Budget for mounted FUSE POSIX stream/mix rows (r2).
    /// Throughput >= 60% of ext4 comparator; p99 stall <= 100 ms.
    pub fn posix_stream_mix() -> Self {
        Self {
            throughput_floor_mb_s: 0.0,
            latency_p95_ceiling_us: 0.0,
            latency_p99_ceiling_us: 100_000.0,
            iops_floor: 0,
            budget_class_ref: "budget.performance_budget_0.posix_filesystem_adapter.stream_mix.r2"
                .into(),
        }
    }
    /// Budget for block-export random queue rows (r3).
    /// Throughput >= 65% of raw block comparator; p99 <= 25 ms.
    pub fn block_random_queue() -> Self {
        Self {
            throughput_floor_mb_s: 0.0,
            latency_p95_ceiling_us: 0.0,
            latency_p99_ceiling_us: 25_000.0,
            iops_floor: 0,
            budget_class_ref: "budget.performance_budget_0.block_volume_adapter.random_queue.r3"
                .into(),
        }
    }
    /// General-purpose budget: 80 MB/s floor, 10 ms p99 ceiling.
    pub fn general_purpose() -> Self {
        Self {
            throughput_floor_mb_s: 80.0,
            latency_p95_ceiling_us: 0.0,
            latency_p99_ceiling_us: 10_000.0,
            iops_floor: 500,
            budget_class_ref: "budget.performance_budget_0.general".into(),
        }
    }
    /// Multi-node degradation budget: absolute floors for distributed operation.
    /// Latency p99 <= 2x single-node baseline (default 20ms absolute floor),
    /// throughput >= 50% of single-node baseline.
    pub fn multi_node_degradation() -> Self {
        Self {
            throughput_floor_mb_s: 0.0,
            latency_p95_ceiling_us: 0.0,
            latency_p99_ceiling_us: 20_000.0,
            iops_floor: 0,
            budget_class_ref: "budget.performance_budget_0.multi_node.degradation.r1".into(),
        }
    }
    /// Metadata workload budget: per-operation latency p99 ceiling.
    /// 50ms max for any single create/stat/rename/unlink operation.
    pub fn metadata_ops() -> Self {
        Self {
            throughput_floor_mb_s: 0.0,
            latency_p95_ceiling_us: 0.0,
            latency_p99_ceiling_us: 50_000.0,
            iops_floor: 0,
            budget_class_ref: "budget.performance_budget_0.metadata_ops.r1".into(),
        }
    }
}

/// Multi-node performance degradation budget: defines acceptable overhead
/// ratios when moving from single-node to multi-node operation.
///
/// Each ratio is a multiplier on the single-node baseline. A ratio of 2.0
/// means the multi-node measurement must be <= 2x the single-node baseline
/// for latency, or >= 0.5x for throughput.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MultiNodeDegradationBudget {
    /// Maximum acceptable latency multiplier (multi-node / single-node).
    /// Default 2.0: multi-node p99 <= 2x single-node p99.
    pub max_latency_overhead_ratio: f64,
    /// Minimum acceptable throughput ratio (multi-node / single-node).
    /// Default 0.50: multi-node throughput >= 50% of single-node.
    pub min_throughput_ratio: f64,
    /// Reference to the budget policy document.
    pub budget_policy_ref: String,
}

impl MultiNodeDegradationBudget {
    /// Release-standard multi-node degradation budget.
    /// Latency overhead <= 2x, throughput retention >= 50%.
    pub fn release_standard() -> Self {
        Self {
            max_latency_overhead_ratio: 2.0,
            min_throughput_ratio: 0.50,
            budget_policy_ref: "budget.performance_budget_0.multi_node.degradation.r1".into(),
        }
    }
}

/// Relative regression lock rules.
/// A row that violates a regression lock opens a bucket even if its
/// absolute floor barely passes.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RegressionLock {
    /// Maximum relative p95 latency regression vs previous variant (fraction).
    /// Default 0.15 (15%).  0.0 means not enforced.
    pub p95_latency_regression_pct: f64,
    /// Maximum relative throughput regression vs previous variant (fraction).
    /// Default 0.10 (10%).  0.0 means not enforced.
    pub throughput_regression_pct: f64,
    /// Maximum tail amplification ratio (p99/p50). Default 10.0.
    /// 0.0 means not enforced.
    pub tail_amplification_max: f64,
}

impl RegressionLock {
    /// Standard release-variant regression locks.
    pub fn release_required() -> Self {
        Self {
            p95_latency_regression_pct: 0.15,
            throughput_regression_pct: 0.10,
            tail_amplification_max: 10.0,
        }
    }
    /// Degraded/fault mode: wider tail allowance.
    pub fn degraded_fault() -> Self {
        Self {
            p95_latency_regression_pct: 0.15,
            throughput_regression_pct: 0.10,
            tail_amplification_max: 20.0,
        }
    }
    /// No regression enforcement.
    pub fn none() -> Self {
        Self {
            p95_latency_regression_pct: 0.0,
            throughput_regression_pct: 0.0,
            tail_amplification_max: 0.0,
        }
    }
}

/// Which budget or regression rule was violated (or a missing-data gap).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BudgetBucket {
    // Absolute threshold violations
    ThroughputFloor,
    LatencyP95Ceiling,
    LatencyP99Ceiling,
    IopsFloor,
    // Relative regression violations
    LatencyRegression,
    ThroughputRegression,
    TailAmplification,
    // Data gaps that prevent evaluation
    NoComparator,
    InvalidNoiseProfile,
    InsufficientSamples,
    MissingArtifact,
}

impl BudgetBucket {
    /// Whether this bucket is release blocking (requires evaluation before release).
    pub fn is_release_blocking(&self) -> bool {
        !matches!(self, Self::NoComparator | Self::InvalidNoiseProfile)
    }
    pub fn label(&self) -> &'static str {
        match self {
            Self::ThroughputFloor => "throughput-floor",
            Self::LatencyP95Ceiling => "latency-p95-ceiling",
            Self::LatencyP99Ceiling => "latency-p99-ceiling",
            Self::IopsFloor => "iops-floor",
            Self::LatencyRegression => "latency-regression",
            Self::ThroughputRegression => "throughput-regression",
            Self::TailAmplification => "tail-amplification",
            Self::NoComparator => "no-comparator",
            Self::InvalidNoiseProfile => "invalid-noise-profile",
            Self::InsufficientSamples => "insufficient-samples",
            Self::MissingArtifact => "missing-artifact",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceGateEntry {
    pub subject: String,
    pub workload: WorkloadEnvelope,
    pub environment: EnvironmentManifest,
    pub validation_tier: ValidationTier,
    pub budget_classes: Vec<BudgetClass>,
    pub numeric_budget: Option<NumericBudget>,
    pub regression_lock: Option<RegressionLock>,
    pub budget_decision: BudgetDecision,
    pub comparators: Vec<ComparatorRef>,
    pub kpis: Vec<MeasuredKpi>,
    pub budget_buckets: Vec<BudgetBucket>,
    pub status: RowStatus,
    pub measurement_source: MeasurementSource,
    pub artifact_requirement: ArtifactRequirement,
    pub artifact_path: Option<String>,
    pub commit_sha: String,
    pub notes: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MeasuredKpi {
    pub ref_id: String,
    pub name: String,
    pub value: f64,
    pub unit: String,
    pub passed: Option<bool>,
    pub percentile: Option<String>,
}
/// Distinguishes whether a row's KPI values came from actual measurement
/// artifacts or placeholder entries that keep the matrix
/// shape alive but do not constitute performance validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MeasurementSource {
    Measured,
    SchemaOnly,
}

/// Minimum validation output requirements for a live-runtime tier row
/// to be admissible as performance gate PASS validation.
/// Kbuild rows are exempt.
/// Live-runtime rows that fail these requirements are forced to
/// FAIL/BLOCKED/REFUSED even if the measurement was attempted.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
pub struct ArtifactRequirement {
    /// Whether a validation output artifact path is required (non-optional for live tiers).
    pub needs_artifact_path: bool,
    /// Whether at least one comparator ref is required.
    pub needs_comparator: bool,
    /// Whether the noise policy must have a valid ref_id (non-empty).
    pub needs_noise_policy: bool,
    /// Whether a non-empty KPI vector is required.
    pub needs_kpis: bool,
    /// Whether the environment manifest must have a real profile_ref.
    pub needs_env_profile: bool,
}

impl ArtifactRequirement {
    /// Full artifact requirement for live-runtime tiers.
    /// A row at MountedUserspace, QemuGuest, MultiProcessDistributed,
    /// QemuModuleLoad, MountedKernelVfs, KernelBlockIo, or FullKernelNoDaemon
    /// must satisfy all of these.
    pub fn live_runtime() -> Self {
        Self {
            needs_artifact_path: true,
            needs_comparator: true,
            needs_noise_policy: true,
            needs_kpis: true,
            needs_env_profile: true,
        }
    }

    /// Relaxed requirement for Kbuild-only rows.
    pub fn none() -> Self {
        Self::default()
    }

    /// Check whether a PerformanceGateEntry satisfies all required artifacts.
    /// Returns a list of unmet requirement names, or empty if all satisfied.
    pub fn check_entry(&self, entry: &PerformanceGateEntry) -> Vec<&'static str> {
        let mut unmet = Vec::new();
        if self.needs_artifact_path && entry.artifact_path.is_none() {
            unmet.push("artifact_path");
        }
        if self.needs_comparator && entry.comparators.is_empty() {
            unmet.push("comparator");
        }
        if self.needs_noise_policy && entry.environment.noise_policy.ref_id.is_empty() {
            unmet.push("noise_policy");
        }
        if self.needs_kpis && entry.kpis.is_empty() {
            unmet.push("kpis");
        }
        if self.needs_env_profile && entry.environment.profile_ref.is_empty() {
            unmet.push("env_profile");
        }
        unmet
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct PendingPerformanceGateEntry {
    pub subject: String,
    pub workload_ref: String,
    pub workload_desc: String,
    pub op_mix: OpMix,
    pub env_profile_ref: String,
    pub host_class: String,
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub kernel_version: String,
    pub storage_backend: String,
    pub cache_mode: String,
    pub noise_policy: NoisePolicy,
    pub validation_tier: ValidationTier,
    pub budget_classes: Vec<BudgetClass>,
    pub commit_sha: String,
}

impl PerformanceGateEntry {
    pub fn pending(input: PendingPerformanceGateEntry) -> Self {
        PerformanceGateEntry {
            subject: input.subject,
            workload: WorkloadEnvelope {
                ref_id: input.workload_ref,
                description: input.workload_desc,
                op_mix: input.op_mix,
            },
            environment: EnvironmentManifest {
                profile_ref: input.env_profile_ref,
                host_class: input.host_class,
                cpu_count: input.cpu_count,
                memory_bytes: input.memory_bytes,
                kernel_version: input.kernel_version,
                storage_backend: input.storage_backend,
                cache_mode: input.cache_mode,
                feature_flags: Vec::new(),
                background_load: None,
                noise_policy: input.noise_policy,
            },
            validation_tier: input.validation_tier,
            budget_classes: input.budget_classes,
            numeric_budget: None,
            regression_lock: None,
            budget_decision: BudgetDecision::Refuse,
            comparators: Vec::new(),
            kpis: Vec::new(),
            budget_buckets: Vec::new(),
            status: RowStatus::Pending,
            measurement_source: MeasurementSource::SchemaOnly,
            artifact_requirement: ArtifactRequirement::none(),
            artifact_path: None,
            commit_sha: input.commit_sha,
            notes: None,
        }
    }

    /// True when this row has live-runtime validation that can close a
    /// performance release gate. Kbuild-only rows never satisfy this even when
    /// marked Pass.
    pub fn is_release_validation(&self) -> bool {
        self.status == RowStatus::Pass
            && self.validation_tier.is_live_runtime()
            && self.measurement_source == MeasurementSource::Measured
    }

    /// Validate that this row satisfies its artifact requirement.
    /// Returns list of unmet requirement names (empty = all satisfied).
    pub fn unmet_artifacts(&self) -> Vec<&'static str> {
        self.artifact_requirement.check_entry(self)
    }

    /// True when this row satisfies all declared artifact requirements.
    pub fn artifacts_satisfied(&self) -> bool {
        self.unmet_artifacts().is_empty()
    }

    /// Evaluate numeric budget thresholds and regression locks against
    /// measured KPI values and comparator baselines.  Opens BudgetBuckets
    /// for each violation.  If any release-blocking bucket is opened and
    /// the row is Pass, downgrades to Fail.
    pub fn evaluate_budget(&mut self) {
        if self.validation_tier.is_code_only() {
            return;
        }

        let mut buckets = Vec::new();

        // --- Absolute numeric budget checks ---
        if let Some(ref budget) = self.numeric_budget {
            // Find throughput KPI
            let tp_kpi = self.kpis.iter().find(|k| {
                k.name.contains("throughput")
                    || k.ref_id.contains("throughput")
                    || k.unit.contains("MB/s")
            });
            if let Some(kpi) = tp_kpi {
                if budget.throughput_floor_mb_s > 0.0 && kpi.value < budget.throughput_floor_mb_s {
                    buckets.push(BudgetBucket::ThroughputFloor);
                }
            } else if budget.throughput_floor_mb_s > 0.0 {
                buckets.push(BudgetBucket::ThroughputFloor);
            }

            // Find p95 latency KPI
            let p95_kpi = self.kpis.iter().find(|k| {
                k.percentile.as_deref() == Some("p95")
                    || k.name.contains("p95")
                    || k.ref_id.contains("p95")
            });
            if let Some(kpi) = p95_kpi {
                if budget.latency_p95_ceiling_us > 0.0 && kpi.value > budget.latency_p95_ceiling_us
                {
                    buckets.push(BudgetBucket::LatencyP95Ceiling);
                }
            }

            // Find p99 latency KPI
            let p99_kpi = self.kpis.iter().find(|k| {
                k.percentile.as_deref() == Some("p99")
                    || k.name.contains("p99")
                    || k.ref_id.contains("p99")
            });
            if let Some(kpi) = p99_kpi {
                if budget.latency_p99_ceiling_us > 0.0 && kpi.value > budget.latency_p99_ceiling_us
                {
                    buckets.push(BudgetBucket::LatencyP99Ceiling);
                }
            }

            // Find IOPS KPI
            let iops_kpi = self.kpis.iter().find(|k| {
                k.unit.contains("iops") || k.name.contains("iops") || k.ref_id.contains("iops")
            });
            if let Some(kpi) = iops_kpi {
                if budget.iops_floor > 0 && (kpi.value as u64) < budget.iops_floor {
                    buckets.push(BudgetBucket::IopsFloor);
                }
            } else if budget.iops_floor > 0 {
                buckets.push(BudgetBucket::IopsFloor);
            }
        }

        // --- Relative regression lock checks ---
        if let Some(ref lock) = self.regression_lock {
            if !self.comparators.is_empty() {
                let prev = &self.comparators[0]; // previous-admitted variant

                // Check latency regression against comparator p95
                if lock.p95_latency_regression_pct > 0.0 {
                    let comp_p95 = prev.baseline_kpis.iter().find(|k| k.name.contains("p95"));
                    let our_p95 = self.kpis.iter().find(|k| {
                        k.percentile.as_deref() == Some("p95")
                            || k.name.contains("p95")
                            || k.ref_id.contains("p95")
                    });
                    if let (Some(ck), Some(ok)) = (comp_p95, our_p95) {
                        if ck.value > 0.0 {
                            let regression = (ok.value - ck.value) / ck.value;
                            if regression > lock.p95_latency_regression_pct {
                                buckets.push(BudgetBucket::LatencyRegression);
                            }
                        }
                    }
                }

                // Check throughput regression against comparator
                if lock.throughput_regression_pct > 0.0 {
                    let comp_tp = prev
                        .baseline_kpis
                        .iter()
                        .find(|k| k.unit.contains("MB/s") || k.name.contains("throughput"));
                    let our_tp = self
                        .kpis
                        .iter()
                        .find(|k| k.name.contains("throughput") || k.unit.contains("MB/s"));
                    if let (Some(ck), Some(ok)) = (comp_tp, our_tp) {
                        if ck.value > 0.0 {
                            let regression = (ck.value - ok.value) / ck.value;
                            if regression > lock.throughput_regression_pct {
                                buckets.push(BudgetBucket::ThroughputRegression);
                            }
                        }
                    }
                }
            }

            // Check tail amplification (p99 / p50 ratio)
            if lock.tail_amplification_max > 0.0 {
                let our_p50 = self.kpis.iter().find(|k| {
                    k.percentile.as_deref() == Some("p50")
                        || k.name.contains("p50")
                        || k.ref_id.contains("p50")
                });
                let our_p99 = self.kpis.iter().find(|k| {
                    k.percentile.as_deref() == Some("p99")
                        || k.name.contains("p99")
                        || k.ref_id.contains("p99")
                });
                if let (Some(k50), Some(k99)) = (our_p50, our_p99) {
                    if k50.value > 0.0 {
                        let ratio = k99.value / k50.value;
                        if ratio > lock.tail_amplification_max {
                            buckets.push(BudgetBucket::TailAmplification);
                        }
                    }
                }
            }
        }

        // --- Data gap buckets ---
        if self.comparators.is_empty() {
            buckets.push(BudgetBucket::NoComparator);
        }
        if self.environment.noise_policy.ref_id.is_empty()
            || self.environment.noise_policy.min_samples < 5
        {
            buckets.push(BudgetBucket::InvalidNoiseProfile);
        }
        if self.kpis.is_empty() {
            buckets.push(BudgetBucket::MissingArtifact);
        }

        self.budget_buckets = buckets;

        // Downgrade PASS to FAIL if any release-blocking bucket opened
        let release_blocked = self.budget_buckets.iter().any(|b| b.is_release_blocking());
        if release_blocked && self.status == RowStatus::Pass {
            self.status = RowStatus::Fail;
            self.budget_decision = BudgetDecision::Fail;
            let bucket_names: Vec<&str> = self
                .budget_buckets
                .iter()
                .filter(|b| b.is_release_blocking())
                .map(|b| b.label())
                .collect();
            let reason = format!("budget violation: {}", bucket_names.join(", "));
            self.notes = Some(match self.notes.take() {
                Some(existing) => format!("{existing}; {reason}"),
                None => reason,
            });
        }
    }

    /// Apply artifact requirement enforcement to this row.
    /// If the row is at a live-runtime tier and was marked Pass but
    /// fails artifact requirements, downgrade status to Refuse and
    /// add a note recording which artifacts are missing.
    pub fn enforce_artifact_requirements(&mut self) {
        if !self.validation_tier.is_live_runtime() {
            return;
        }
        if self.artifact_requirement.needs_artifact_path
            || self.artifact_requirement.needs_comparator
            || self.artifact_requirement.needs_noise_policy
            || self.artifact_requirement.needs_kpis
            || self.artifact_requirement.needs_env_profile
        {
            let unmet = self.unmet_artifacts();
            if !unmet.is_empty() {
                let reason = format!("missing artifacts: {}", unmet.join(", "));
                if self.status == RowStatus::Pass {
                    self.status = RowStatus::Refuse;
                    self.budget_decision = BudgetDecision::Refuse;
                    self.measurement_source = MeasurementSource::SchemaOnly;
                    self.notes = Some(match self.notes.take() {
                        Some(existing) => format!("{existing}; {reason}"),
                        None => reason,
                    });
                }
            }
        }
    }
}

/// Return the default numeric budget appropriate for a given subject.
/// Returns None for subjects that have no numeric budget class yet.
pub fn default_numeric_budget_for(subject: &str) -> Option<NumericBudget> {
    match subject {
        "mounted-fuse" | "local-filesystem" => Some(NumericBudget::posix_stream_mix()),
        "ublk-direct" | "ublk-ext4" => Some(NumericBudget::block_random_queue()),
        "local-object-store" | "transport" | "recovery-rebuild" => {
            Some(NumericBudget::general_purpose())
        }
        // Kernel rows blocked; no budget enforcement until executable
        "mounted-fuse-metadata" => Some(NumericBudget::metadata_ops()),
        "kernel-kmod-vfs" | "kernel-block-kmod" => None,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn np() -> NoisePolicy {
        NoisePolicy {
            ref_id: "n".into(),
            warmup_samples: 5,
            min_samples: 30,
            max_cv: 0.05,
        }
    }
    fn om() -> OpMix {
        OpMix {
            read_pct: 70,
            write_pct: 20,
            metadata_pct: 5,
            sync_pct: 5,
            concurrency: 4,
        }
    }
    #[test]
    fn pending_entry_has_correct_defaults() {
        let e = PerformanceGateEntry::pending(PendingPerformanceGateEntry {
            subject: "fs".into(),
            workload_ref: "e1".into(),
            workload_desc: "rw".into(),
            op_mix: om(),
            env_profile_ref: "e2".into(),
            host_class: "h".into(),
            cpu_count: 4,
            memory_bytes: 8_589_934_592,
            kernel_version: "L7".into(),
            storage_backend: "los".into(),
            cache_mode: "none".into(),
            noise_policy: np(),
            validation_tier: ValidationTier::QemuGuest,
            budget_classes: vec![],
            commit_sha: "abc".into(),
        });
        assert_eq!(e.status, RowStatus::Pending);
        assert_eq!(e.budget_decision, BudgetDecision::Refuse);
    }
    #[test]
    fn validation_tier_is_live_runtime() {
        assert!(ValidationTier::MountedUserspace.is_live_runtime());
        assert!(!ValidationTier::Kbuild.is_live_runtime());
    }
    #[test]
    fn validation_tier_code_only() {
        assert!(ValidationTier::Kbuild.is_code_only());
        assert!(!ValidationTier::MountedUserspace.is_code_only());
    }
    #[test]
    fn noise_policy_serialization_roundtrip() {
        let json = serde_json::to_string(&np()).unwrap();
        let np2: NoisePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(np(), np2);
    }
    #[test]
    fn entry_serialization_roundtrip() {
        let e = PerformanceGateEntry::pending(PendingPerformanceGateEntry {
            subject: "fs".into(),
            workload_ref: "e1".into(),
            workload_desc: "rw".into(),
            op_mix: om(),
            env_profile_ref: "e2".into(),
            host_class: "h".into(),
            cpu_count: 4,
            memory_bytes: 8_589_934_592,
            kernel_version: "L7".into(),
            storage_backend: "nvme".into(),
            cache_mode: "wb".into(),
            noise_policy: np(),
            validation_tier: ValidationTier::MountedUserspace,
            budget_classes: vec![],
            commit_sha: "abc".into(),
        });
        let json = serde_json::to_string_pretty(&e).unwrap();
        let e2: PerformanceGateEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e.subject, e2.subject);
    }
}
