// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Performance comparator matrix consolidation -- groups performance gate
//! rows by product lane (userspace, storage, multi-node, kernel) and
//! produces a unified gate receipt with lane-aware summaries.
//!
//! This module implements the REL-VAL-005 consolidation contract: each
//! lane-specific performance gate (#6307 FUSE, #6331 Storage, #6343 Multi-node)
//! feeds rows into this consolidation view, which renders the unified
//! comparator matrix with blocker documentation.

use super::degradation_budget::DegradationComparison;
use super::gate_entry::MultiNodeDegradationBudget;
use super::gate_entry::{
    ArtifactRequirement, BudgetClass, ComparatorRef, EnvironmentManifest, MeasuredKpi,
    MeasurementSource, NoisePolicy, OpMix, PendingPerformanceGateEntry, PerformanceGateEntry,
    RowStatus,
};
use super::matrix::{PerformanceMatrix, REQUIRED_SUBJECTS};
use super::validation_tier::ValidationTier;
use serde::{Deserialize, Serialize};

/// Product lane for organising performance gate subjects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SubjectLane {
    /// Userspace POSIX / block-device paths: local-filesystem, mounted-fuse,
    /// ublk-direct, ublk-ext4.
    Userspace,
    /// Storage core paths: local-object-store, transport, recovery-rebuild.
    Storage,
    /// Multi-node distributed paths: transport (multi-node view),
    /// recovery-rebuild (multi-node view).
    MultiNode,
    /// Kernel module paths: kernel-kmod-vfs, kernel-block-kmod.
    Kernel,
}

impl SubjectLane {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Userspace => "userspace",
            Self::Storage => "storage",
            Self::MultiNode => "multi-node",
            Self::Kernel => "kernel",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Userspace => "FUSE, ublk, and local-filesystem POSIX/block paths",
            Self::Storage => "local object-store, transport, and recovery/rebuild paths",
            Self::MultiNode => "multi-node transport, placement, and recovery paths",
            Self::Kernel => "kernel VFS, block, and no-daemon paths",
        }
    }
}

/// Map each required subject to its primary product lane.
pub fn subject_lane(subject: &str) -> SubjectLane {
    match subject {
        "local-filesystem" | "mounted-fuse" | "ublk-direct" | "ublk-ext4" => SubjectLane::Userspace,
        "local-object-store" | "transport" => SubjectLane::Storage,
        "recovery-rebuild" => SubjectLane::MultiNode,
        "kernel-kmod-vfs" | "kernel-block-kmod" => SubjectLane::Kernel,
        _ => SubjectLane::Storage,
    }
}

/// Consolidated view of a single subject across lanes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidatedRow {
    pub subject: String,
    pub lane: SubjectLane,
    pub workload_ref: String,
    pub validation_tier_label: String,
    pub status: RowStatus,
    pub measurement_source: MeasurementSource,
    pub artifacts_satisfied: bool,
    pub budget_buckets: Vec<String>,
    pub comparators: Vec<ComparatorRef>,
    pub kpis: Vec<MeasuredKpi>,
    pub artifact_path: Option<String>,
    pub blocker: Option<String>,
    pub notes: Option<String>,
}

impl From<&PerformanceGateEntry> for ConsolidatedRow {
    fn from(entry: &PerformanceGateEntry) -> Self {
        let lane = subject_lane(&entry.subject);
        let buckets: Vec<String> = entry
            .budget_buckets
            .iter()
            .map(|b| b.label().to_string())
            .collect();
        let blocker = if entry.status != RowStatus::Pass {
            let mut reasons = Vec::new();
            if entry.measurement_source == MeasurementSource::SchemaOnly {
                reasons.push("no-measured-data".to_string());
            }
            if !entry.artifacts_satisfied() {
                reasons.push(format!(
                    "missing-artifacts: {}",
                    entry.unmet_artifacts().join(", ")
                ));
            }
            if !buckets.is_empty() {
                reasons.push(format!("budget-gaps: {}", buckets.join(", ")));
            }
            if reasons.is_empty() {
                reasons.push("pending".to_string());
            }
            Some(reasons.join("; "))
        } else {
            None
        };
        ConsolidatedRow {
            subject: entry.subject.clone(),
            lane,
            workload_ref: entry.workload.ref_id.clone(),
            validation_tier_label: entry.validation_tier.label().to_string(),
            status: entry.status,
            measurement_source: entry.measurement_source,
            artifacts_satisfied: entry.artifacts_satisfied(),
            budget_buckets: buckets,
            comparators: entry.comparators.clone(),
            kpis: entry.kpis.clone(),
            artifact_path: entry.artifact_path.clone(),
            blocker,
            notes: entry.notes.clone(),
        }
    }
}

/// Multi-node degradation budget comparison result.
/// Captures the single-node vs multi-node overhead evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradationSummary {
    /// Whether the degradation comparison was evaluated.
    pub evaluated: bool,
    /// Overall budget decision.
    pub decision: String,
    /// Budget buckets that were violated (empty if passed).
    pub buckets: Vec<String>,
    /// Number of single-node baseline KPIs.
    pub single_node_kpi_count: usize,
    /// Number of multi-node measured KPIs (0 if no runtime validation).
    pub multi_node_kpi_count: usize,
    /// Human-readable summary of the comparison.
    pub summary: String,
}
/// Lane-level summary for the consolidated comparator matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneSummary {
    pub lane: SubjectLane,
    pub total_rows: usize,
    pub pass: usize,
    pub fail: usize,
    pub refuse: usize,
    pub pending: usize,
    pub runtime_pass: usize,
    pub code_only_pass: usize,
    pub artifact_gap: usize,
    pub budget_gap: usize,
}

/// Full consolidated performance comparator matrix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsolidatedMatrix {
    pub commit_sha: String,
    pub generated_at: String,
    pub matrix_ref: String,
    pub lanes: Vec<LaneSummary>,
    pub rows: Vec<ConsolidatedRow>,
    pub missing_subjects: Vec<String>,
    pub invariant_holds: bool,
    pub perf_gate_ready: bool,
    pub degradation_summary: Option<DegradationSummary>,
}

impl ConsolidatedMatrix {
    pub const MATRIX_REF: &'static str =
        "matrix.performance.budget.performance_budget_0.consolidated";

    /// Build a consolidated matrix from an existing PerformanceMatrix.
    pub fn from_matrix(matrix: &PerformanceMatrix) -> Self {
        let rows: Vec<ConsolidatedRow> = matrix.rows.iter().map(ConsolidatedRow::from).collect();
        let missing: Vec<String> = matrix
            .missing_required_subjects()
            .iter()
            .map(|s| s.to_string())
            .collect();
        let invariant = missing.is_empty();

        let mut lanes = Vec::new();
        for lane in &[
            SubjectLane::Userspace,
            SubjectLane::Storage,
            SubjectLane::MultiNode,
            SubjectLane::Kernel,
        ] {
            let lane_rows: Vec<&ConsolidatedRow> =
                rows.iter().filter(|r| r.lane == *lane).collect();
            let total = lane_rows.len();
            if total == 0 {
                continue;
            }
            let pass = lane_rows
                .iter()
                .filter(|r| r.status == RowStatus::Pass)
                .count();
            let fail = lane_rows
                .iter()
                .filter(|r| r.status == RowStatus::Fail)
                .count();
            let refuse = lane_rows
                .iter()
                .filter(|r| r.status == RowStatus::Refuse)
                .count();
            let pending = lane_rows
                .iter()
                .filter(|r| r.status == RowStatus::Pending)
                .count();
            let runtime_pass = lane_rows
                .iter()
                .filter(|r| {
                    r.status == RowStatus::Pass
                        && r.measurement_source == MeasurementSource::Measured
                })
                .count();
            let code_only_pass = pass.saturating_sub(runtime_pass);
            let artifact_gap = lane_rows
                .iter()
                .filter(|r| !r.artifacts_satisfied && r.status != RowStatus::Pass)
                .count();
            let budget_gap = lane_rows
                .iter()
                .filter(|r| !r.budget_buckets.is_empty())
                .count();
            lanes.push(LaneSummary {
                lane: *lane,
                total_rows: total,
                pass,
                fail,
                refuse,
                pending,
                runtime_pass,
                code_only_pass,
                artifact_gap,
                budget_gap,
            });
        }

        let perf_gate_ready = invariant
            && lanes.iter().all(|l| l.runtime_pass > 0)
            && rows.iter().any(|r| {
                r.status == RowStatus::Pass && r.measurement_source == MeasurementSource::Measured
            });

        ConsolidatedMatrix {
            commit_sha: matrix.commit_sha.clone(),
            generated_at: matrix.generated_at.clone(),
            matrix_ref: Self::MATRIX_REF.to_string(),
            lanes,
            rows,
            missing_subjects: missing,
            invariant_holds: invariant,
            degradation_summary: None,
            perf_gate_ready,
        }
    }

    /// Evaluate multi-node degradation budget by comparing single-node
    /// baseline KPIs against multi-node runtime KPIs.
    pub fn add_degradation_evaluation(
        &mut self,
        single_node_kpis: Vec<MeasuredKpi>,
        multi_node_kpis: Vec<MeasuredKpi>,
        budget: MultiNodeDegradationBudget,
    ) {
        let comparison = DegradationComparison::evaluate(single_node_kpis, multi_node_kpis, budget);
        let buckets: Vec<String> = comparison
            .buckets
            .iter()
            .map(|b| b.label().to_string())
            .collect();
        self.degradation_summary = Some(DegradationSummary {
            evaluated: true,
            decision: format!("{:?}", comparison.decision),
            buckets,
            single_node_kpi_count: comparison.single_node_kpis.len(),
            multi_node_kpi_count: comparison.multi_node_kpis.len(),
            summary: comparison.summary_line(),
        });
    }
    /// Build an empty consolidated matrix for the current commit with all
    /// required subjects as pending.  Useful as an initial state before
    /// lane-specific gates populate rows.
    pub fn empty(commit_sha: impl Into<String>, generated_at: impl Into<String>) -> Self {
        let mut matrix = PerformanceMatrix::new(commit_sha, generated_at);
        for subject in REQUIRED_SUBJECTS {
            let lane = subject_lane(subject);
            let op_mix = match lane {
                SubjectLane::Userspace => OpMix {
                    read_pct: 70,
                    write_pct: 20,
                    metadata_pct: 5,
                    sync_pct: 5,
                    concurrency: 4,
                },
                SubjectLane::Storage => OpMix {
                    read_pct: 50,
                    write_pct: 40,
                    metadata_pct: 5,
                    sync_pct: 5,
                    concurrency: 4,
                },
                SubjectLane::MultiNode => OpMix {
                    read_pct: 40,
                    write_pct: 40,
                    metadata_pct: 10,
                    sync_pct: 10,
                    concurrency: 4,
                },
                SubjectLane::Kernel => OpMix {
                    read_pct: 60,
                    write_pct: 30,
                    metadata_pct: 5,
                    sync_pct: 5,
                    concurrency: 4,
                },
            };
            let np = NoisePolicy {
                ref_id: "noise.performance_budget_0.reference_host.n2".into(),
                warmup_samples: 10,
                min_samples: 30,
                max_cv: 0.05,
            };
            let env = EnvironmentManifest {
                profile_ref: "env.performance_budget_0.single_node_ref.e2".into(),
                host_class: "qemu-guest".into(),
                cpu_count: 4,
                memory_bytes: 8_589_934_592,
                kernel_version: "Linux 7.0".into(),
                storage_backend: "local-object-store".into(),
                cache_mode: "none".into(),
                feature_flags: vec![],
                background_load: None,
                noise_policy: np,
            };
            let bc = BudgetClass {
                ref_id: format!("budget.performance_budget_0.{}.general", lane.label()),
                kpi_family: "kpi.performance_budget_0.throughput.floor".into(),
                floor_description: "pending throughput floor".into(),
                release_blocking: true,
            };
            let mut entry = PerformanceGateEntry::pending(PendingPerformanceGateEntry {
                subject: (*subject).into(),
                workload_ref: format!("envelope.performance_budget_0.{}.e1", lane.label()),
                workload_desc: format!("{} workload envelope", lane.label()),
                op_mix,
                env_profile_ref: env.profile_ref.clone(),
                host_class: env.host_class.clone(),
                cpu_count: env.cpu_count,
                memory_bytes: env.memory_bytes,
                kernel_version: env.kernel_version.clone(),
                storage_backend: env.storage_backend.clone(),
                cache_mode: env.cache_mode.clone(),
                noise_policy: env.noise_policy.clone(),
                validation_tier: ValidationTier::Kbuild,
                budget_classes: vec![bc],
                commit_sha: "unknown".into(),
            });
            entry.artifact_requirement = ArtifactRequirement::live_runtime();
            entry.notes = Some(format!(
                "blocked: no measured {} performance data",
                lane.label()
            ));
            matrix.add_row(entry);
        }
        ConsolidatedMatrix::from_matrix(&matrix)
    }

    /// Render the consolidated matrix as markdown.
    pub fn render_markdown(&self) -> String {
        let perf_gate_label = if self.perf_gate_ready {
            "READY"
        } else {
            "NOT READY"
        };
        let mut o = format!(
            "# Performance Comparator Matrix (Consolidated) — {}\n\n\
             **Commit**: `{}` | **Generated**: {}\n\n\
             Performance gate: {}\n\n\
             **Subject completeness**: {}\n\n",
            self.matrix_ref,
            self.commit_sha,
            self.generated_at,
            perf_gate_label,
            if self.invariant_holds { "yes" } else { "no" },
        );

        if !self.missing_subjects.is_empty() {
            o.push_str(&format!(
                "**Missing subjects**: {}\n\n",
                self.missing_subjects.join(", ")
            ));
        }

        o.push_str("## Lane Summaries\n\n");
        o.push_str("| Lane | Rows | Pass | Fail | Refuse | Pending | Runtime Pass | Artifact Gap | Budget Gap |\n");
        o.push_str("|------|------|------|------|--------|---------|--------------|--------------|------------|\n");
        for lane in &self.lanes {
            o.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                lane.lane.label(),
                lane.total_rows,
                lane.pass,
                lane.fail,
                lane.refuse,
                lane.pending,
                lane.runtime_pass,
                lane.artifact_gap,
                lane.budget_gap,
            ));
        }

        o.push_str("\n## Comparator Rows\n\n");
        let lane_order = [
            SubjectLane::Userspace,
            SubjectLane::Storage,
            SubjectLane::MultiNode,
            SubjectLane::Kernel,
        ];
        for lane in &lane_order {
            let lane_rows: Vec<&ConsolidatedRow> =
                self.rows.iter().filter(|r| r.lane == *lane).collect();
            if lane_rows.is_empty() {
                continue;
            }
            o.push_str(&format!(
                "### {} — {}\n\n",
                lane.label().to_uppercase(),
                lane.description()
            ));
            o.push_str("| Subject | Tier | Status | Source | Artifacts | Buckets | Blocker |\n");
            o.push_str("|---------|------|--------|--------|-----------|---------|--------|\n");
            for row in &lane_rows {
                let source = match row.measurement_source {
                    MeasurementSource::Measured => "measured",
                    MeasurementSource::SchemaOnly => "schema",
                };
                let artifacts = if row.artifacts_satisfied { "ok" } else { "gap" };
                let buckets = if row.budget_buckets.is_empty() {
                    "\u{2014}".to_string()
                } else {
                    row.budget_buckets.join(", ")
                };
                let blocker = row.blocker.as_deref().unwrap_or("\u{2014}");
                o.push_str(&format!(
                    "| {} | {} | {:?} | {} | {} | {} | {} |\n",
                    row.subject,
                    row.validation_tier_label,
                    row.status,
                    source,
                    artifacts,
                    buckets,
                    blocker,
                ));
            }
            o.push('\n');
        }

        let all_notes: Vec<&str> = self
            .rows
            .iter()
            .filter_map(|r| r.notes.as_deref())
            .collect();
        if !all_notes.is_empty() {
            o.push_str("## Notes\n\n");
            for note in &all_notes {
                o.push_str(&format!("- {note}\n"));
            }
            o.push('\n');
        }

        // --- Multi-node degradation budget ---
        if let Some(ref ds) = self.degradation_summary {
            o.push_str("\n## Multi-Node Degradation Budget\n\n");
            o.push_str(&format!("**Evaluated**: {}\n", ds.evaluated));
            o.push_str(&format!("**Decision**: {}\n", ds.decision));
            o.push_str(&format!(
                "**Single-node KPIs**: {}\n",
                ds.single_node_kpi_count
            ));
            o.push_str(&format!(
                "**Multi-node KPIs**: {}\n",
                ds.multi_node_kpi_count
            ));
            if !ds.buckets.is_empty() {
                o.push_str(&format!("**Buckets**: {}\n", ds.buckets.join(", ")));
            }
            o.push_str(&format!("**Summary**: {}\n\n", ds.summary));
        }

        o
    }
}

#[cfg(test)]
mod tests {
    use super::super::gate_entry::MeasurementSource;
    use super::super::matrix::REQUIRED_SUBJECTS;
    use super::*;

    fn pending_entry(subject: &str, _lane: SubjectLane) -> PerformanceGateEntry {
        let np = NoisePolicy {
            ref_id: "n2".into(),
            warmup_samples: 10,
            min_samples: 30,
            max_cv: 0.05,
        };
        let op = OpMix {
            read_pct: 70,
            write_pct: 20,
            metadata_pct: 5,
            sync_pct: 5,
            concurrency: 4,
        };
        PerformanceGateEntry::pending(PendingPerformanceGateEntry {
            subject: subject.into(),
            workload_ref: "e1".into(),
            workload_desc: "test".into(),
            op_mix: op,
            env_profile_ref: "e2".into(),
            host_class: "h".into(),
            cpu_count: 4,
            memory_bytes: 8_589_934_592,
            kernel_version: "L7".into(),
            storage_backend: "los".into(),
            cache_mode: "none".into(),
            noise_policy: np,
            validation_tier: ValidationTier::Kbuild,
            budget_classes: vec![],
            commit_sha: "abc".into(),
        })
    }

    #[test]
    fn lane_assignment() {
        assert_eq!(subject_lane("mounted-fuse"), SubjectLane::Userspace);
        assert_eq!(subject_lane("ublk-direct"), SubjectLane::Userspace);
        assert_eq!(subject_lane("local-object-store"), SubjectLane::Storage);
        assert_eq!(subject_lane("transport"), SubjectLane::Storage);
        assert_eq!(subject_lane("recovery-rebuild"), SubjectLane::MultiNode);
        assert_eq!(subject_lane("kernel-kmod-vfs"), SubjectLane::Kernel);
    }

    #[test]
    fn consolidated_row_from_pending_entry() {
        let entry = pending_entry("mounted-fuse", SubjectLane::Userspace);
        let row = ConsolidatedRow::from(&entry);
        assert_eq!(row.subject, "mounted-fuse");
        assert_eq!(row.lane, SubjectLane::Userspace);
        assert_eq!(row.status, RowStatus::Pending);
        assert_eq!(row.measurement_source, MeasurementSource::SchemaOnly);
        assert!(row.blocker.is_some());
    }

    #[test]
    fn empty_consolidated_matrix() {
        let cm = ConsolidatedMatrix::empty("abc123", "2026-05-22T00:00:00Z");
        assert_eq!(cm.rows.len(), REQUIRED_SUBJECTS.len());
        assert!(cm.invariant_holds);
        assert!(!cm.perf_gate_ready);
        let lane_labels: Vec<&str> = cm.lanes.iter().map(|l| l.lane.label()).collect();
        assert!(lane_labels.contains(&"userspace"));
        assert!(lane_labels.contains(&"storage"));
        assert!(lane_labels.contains(&"multi-node"));
        assert!(lane_labels.contains(&"kernel"));
    }

    #[test]
    fn consolidated_markdown_renders() {
        let cm = ConsolidatedMatrix::empty("abc123", "2026-05-22T00:00:00Z");
        let md = cm.render_markdown();
        assert!(md.contains("Performance gate: NOT READY"));
        assert!(md.contains("NOT READY"));
        assert!(md.contains("USERSPACE"));
        assert!(md.contains("STORAGE"));
        assert!(md.contains("MULTI-NODE"));
        assert!(md.contains("KERNEL"));
        assert!(md.contains("mounted-fuse"));
        assert!(md.contains("ublk-direct"));
        assert!(md.contains("local-object-store"));
    }

    #[test]
    fn empty_consolidated_serialization() {
        let cm = ConsolidatedMatrix::empty("abc123", "2026-05-22T00:00:00Z");
        let json = serde_json::to_string_pretty(&cm).unwrap();
        let cm2: ConsolidatedMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(cm.rows.len(), cm2.rows.len());
        assert_eq!(cm.lanes.len(), cm2.lanes.len());
    }

    #[test]
    fn lane_summary_counts() {
        let cm = ConsolidatedMatrix::empty("abc123", "2026-05-22T00:00:00Z");
        let userspace = cm
            .lanes
            .iter()
            .find(|l| l.lane == SubjectLane::Userspace)
            .unwrap();
        assert_eq!(userspace.total_rows, 4);
        assert_eq!(userspace.pending, 4);
        assert_eq!(userspace.pass, 0);
    }
}
