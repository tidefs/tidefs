// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::benchmark_harness::BenchmarkResult;
use super::comparator_harness::{ComparatorHarness, ComparatorManifest, ComparatorRun};
use super::consolidation::DegradationSummary;
use super::degradation_budget::DegradationComparison;
use super::gate_entry::{
    default_numeric_budget_for, ArtifactRequirement, BudgetClass, BudgetDecision, ComparatorRef,
    EnvironmentManifest, MeasuredKpi, MeasurementSource, MultiNodeDegradationBudget, OpMix,
    PendingPerformanceGateEntry, PerformanceGateEntry, RegressionLock, RowStatus,
};
use super::matrix::{PerformanceMatrix, REQUIRED_SUBJECTS};
use super::validation_tier::ValidationTier;
use crate::carrier_comparison::{self, CarrierComparisonReport};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RunVerdict {
    Passed,
    Failed,
    Refused,
    Skipped,
}
#[derive(Debug)]
pub struct GateRunner {
    pub shared_env: EnvironmentManifest,
    pub commit_sha: String,
    entries: Vec<PerformanceGateEntry>,
    comparator_entries: Vec<ComparatorRun>,
    notes: Vec<String>,
    degradation: Option<DegradationSummary>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct GateRunRecord {
    pub subject: String,
    pub workload_ref: String,
    pub workload_desc: String,
    pub op_mix: OpMix,
    pub validation_tier: ValidationTier,
    pub budget_classes: Vec<BudgetClass>,
    pub verdict: RunVerdict,
    pub kpis: Vec<MeasuredKpi>,
    pub artifact_path: Option<String>,
    pub initial_comparators: Vec<ComparatorRef>,
    pub skip_numeric_budget: bool,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateReceipt {
    pub matrix_ref: String,
    pub commit_sha: String,
    pub generated_at: String,
    pub rows: Vec<GateReceiptRow>,
    pub comparator_runs: Vec<ComparatorRun>,
    pub summary: ReceiptSummary,
    pub perf_gate_ready: bool,
    pub invariant_holds: bool,
    pub missing_subjects: Vec<String>,
    pub notes: Vec<String>,
    pub artifact_path: Option<String>,
    pub degradation_summary: Option<DegradationSummary>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateReceiptRow {
    pub subject: String,
    pub workload_ref: String,
    pub environment_ref: String,
    pub validation_tier: String,
    pub verdict: RunVerdict,
    pub budget_decision: BudgetDecision,
    pub kpis: Vec<MeasuredKpi>,
    pub artifact_path: Option<String>,
    pub artifacts_satisfied: bool,
    pub budget_buckets: Vec<String>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub refused: usize,
    pub skipped: usize,
    pub runtime_pass: usize,
    pub code_only_pass: usize,
    pub artifact_gap: usize,
    pub budget_gap: usize,
}

impl GateReceipt {
    /// Render this receipt as a complete markdown performance gate report.
    /// Surfaces measurement sources, artifacts, comparators, budget buckets,
    /// and performance-gate readiness in a single view.
    pub fn render_markdown(&self) -> String {
        let mut md = String::new();
        let perf_gate_label = if self.perf_gate_ready {
            "READY"
        } else {
            "NOT READY"
        };
        md.push_str(&format!(
            "# Performance Gate Receipt — {}

",
            self.matrix_ref
        ));
        md.push_str(&format!(
            "**Commit**: `{}` | **Generated**: {}
",
            self.commit_sha, self.generated_at
        ));
        md.push_str(&format!("Performance gate: {perf_gate_label}\n"));
        md.push_str(&format!(
            "**Subject completeness**: {}
",
            if self.invariant_holds { "yes" } else { "no" }
        ));
        if !self.missing_subjects.is_empty() {
            md.push_str(&format!(
                "**Missing subjects**: {}
",
                self.missing_subjects.join(", ")
            ));
        }
        md.push_str(
            "
## Summary

",
        );
        md.push_str(
            "| Metric | Count |
|--------|-------|
",
        );
        md.push_str(&format!(
            "| Total rows | {} |
",
            self.summary.total
        ));
        md.push_str(&format!(
            "| Passed (runtime) | {} |
",
            self.summary.runtime_pass
        ));
        md.push_str(&format!(
            "| Passed (code-only) | {} |
",
            self.summary.code_only_pass
        ));
        md.push_str(&format!(
            "| Failed | {} |
",
            self.summary.failed
        ));
        md.push_str(&format!(
            "| Refused | {} |
",
            self.summary.refused
        ));
        md.push_str(&format!(
            "| Skipped | {} |
",
            self.summary.skipped
        ));
        md.push_str(&format!(
            "| Artifact gap | {} |
",
            self.summary.artifact_gap
        ));
        md.push_str(&format!(
            "| Budget gap | {} |
",
            self.summary.budget_gap
        ));

        md.push_str(
            "
## Validation Rows

",
        );
        md.push_str(
            "| Subject | Tier | Verdict | Budget | Artifacts OK | Budget Buckets |
",
        );
        md.push_str(
            "|---|---|---|---|---|---|
",
        );
        for row in &self.rows {
            let buckets = if row.budget_buckets.is_empty() {
                "—".to_string()
            } else {
                row.budget_buckets.join(", ")
            };
            md.push_str(&format!(
                "| {} | {} | {:?} | {:?} | {} | {} |
",
                row.subject,
                row.validation_tier,
                row.verdict,
                row.budget_decision,
                if row.artifacts_satisfied { "yes" } else { "no" },
                buckets
            ));
        }

        if !self.comparator_runs.is_empty() {
            md.push_str(
                "
## Comparator Runs

",
            );
            md.push_str(
                "| Ref ID | Executed | KPIs | Blocker |
",
            );
            md.push_str(
                "|---|---|---|---|
",
            );
            for cr in &self.comparator_runs {
                let kpi_count = cr.baseline_kpis.len();
                let blocker = cr.blocker.as_deref().unwrap_or("—");
                md.push_str(&format!(
                    "| {} | {} | {} | {} |
",
                    cr.ref_id,
                    if cr.executed { "yes" } else { "no" },
                    kpi_count,
                    blocker
                ));
            }
        }

        // --- Multi-node degradation budget ---
        if let Some(ref ds) = self.degradation_summary {
            md.push_str(
                "
## Multi-Node Degradation Budget

",
            );
            md.push_str(&format!(
                "**Evaluated**: {}
",
                ds.evaluated
            ));
            md.push_str(&format!(
                "**Decision**: {}
",
                ds.decision
            ));
            md.push_str(&format!(
                "**Single-node KPIs**: {}
",
                ds.single_node_kpi_count
            ));
            md.push_str(&format!(
                "**Multi-node KPIs**: {}
",
                ds.multi_node_kpi_count
            ));
            if !ds.buckets.is_empty() {
                md.push_str(&format!(
                    "**Buckets**: {}
",
                    ds.buckets.join(", ")
                ));
            }
            md.push_str(&format!(
                "**Summary**: {}
",
                ds.summary
            ));
            if ds.evaluated && ds.decision == "Pass" {
                md.push_str(
                    "
**Verdict**: Multi-node overhead within approved degradation budget.
",
                );
            } else if ds.evaluated && ds.decision == "Fail" {
                md.push_str(
                    "
**Verdict**: Multi-node overhead exceeds degradation budget.
",
                );
            }
        }

        if !self.notes.is_empty() {
            md.push_str(
                "
## Notes

",
            );
            for note in &self.notes {
                md.push_str(&format!(
                    "- {note}
"
                ));
            }
        }

        md
    }
}

impl GateRunner {
    pub fn new(env: EnvironmentManifest, commit_sha: impl Into<String>) -> Self {
        GateRunner {
            shared_env: env,
            commit_sha: commit_sha.into(),
            entries: Vec::new(),
            comparator_entries: Vec::new(),
            notes: Vec::new(),
            degradation: None,
        }
    }
    pub fn note(&mut self, note: impl Into<String>) {
        self.notes.push(note.into());
    }
    pub fn record(&mut self, record: GateRunRecord) {
        let GateRunRecord {
            subject,
            workload_ref,
            workload_desc,
            op_mix,
            validation_tier,
            budget_classes,
            verdict,
            kpis,
            artifact_path,
            initial_comparators,
            skip_numeric_budget,
        } = record;
        let bd = match verdict {
            RunVerdict::Passed => BudgetDecision::Pass,
            RunVerdict::Failed => BudgetDecision::Fail,
            _ => BudgetDecision::Refuse,
        };
        let st = match verdict {
            RunVerdict::Passed => RowStatus::Pass,
            RunVerdict::Failed => RowStatus::Fail,
            _ => RowStatus::Refuse,
        };
        let ms = if validation_tier.is_live_runtime()
            && verdict == RunVerdict::Passed
            && !kpis.is_empty()
        {
            MeasurementSource::Measured
        } else {
            MeasurementSource::SchemaOnly
        };
        let artifact_req = if validation_tier.is_live_runtime() {
            ArtifactRequirement::live_runtime()
        } else {
            ArtifactRequirement::none()
        };
        let mut e = PerformanceGateEntry::pending(PendingPerformanceGateEntry {
            subject,
            workload_ref,
            workload_desc,
            op_mix,
            env_profile_ref: self.shared_env.profile_ref.clone(),
            host_class: self.shared_env.host_class.clone(),
            cpu_count: self.shared_env.cpu_count,
            memory_bytes: self.shared_env.memory_bytes,
            kernel_version: self.shared_env.kernel_version.clone(),
            storage_backend: self.shared_env.storage_backend.clone(),
            cache_mode: self.shared_env.cache_mode.clone(),
            noise_policy: self.shared_env.noise_policy.clone(),
            validation_tier,
            budget_classes,
            commit_sha: self.commit_sha.clone(),
        });
        e.kpis = kpis;
        e.budget_decision = bd;
        e.status = st;
        e.artifact_path = artifact_path;
        e.measurement_source = ms;
        e.artifact_requirement = artifact_req;
        // Apply default numeric budget and regression lock for this subject
        e.numeric_budget = if skip_numeric_budget {
            None
        } else {
            default_numeric_budget_for(&e.subject)
        };
        e.regression_lock = Some(if validation_tier.is_live_runtime() {
            RegressionLock::release_required()
        } else {
            RegressionLock::none()
        });
        e.comparators = initial_comparators;
        e.evaluate_budget();
        e.enforce_artifact_requirements();
        self.entries.push(e);
    }
    pub fn record_benchmark(
        &mut self,
        result: &BenchmarkResult,
        workload_ref: impl Into<String>,
        workload_desc: impl Into<String>,
        op_mix: OpMix,
    ) {
        let v = result.verdict();
        self.record(GateRunRecord {
            subject: result.subject.clone(),
            workload_ref: workload_ref.into(),
            workload_desc: workload_desc.into(),
            op_mix,
            validation_tier: result.validation_tier,
            budget_classes: Vec::new(),
            verdict: v,
            kpis: result.kpis.clone(),
            artifact_path: None,
            initial_comparators: Vec::new(),
            skip_numeric_budget: false,
        });
        if !result.executed {
            self.notes
                .push(format!("{}: {}", result.subject, result.description));
        }
    }
    pub fn record_refused(
        &mut self,
        subject: impl Into<String>,
        workload_ref: impl Into<String>,
        workload_desc: impl Into<String>,
        op_mix: OpMix,
        validation_tier: ValidationTier,
        reason: impl Into<String>,
    ) {
        self.record(GateRunRecord {
            subject: subject.into(),
            workload_ref: workload_ref.into(),
            workload_desc: workload_desc.into(),
            op_mix,
            validation_tier,
            budget_classes: Vec::new(),
            verdict: RunVerdict::Refused,
            kpis: Vec::new(),
            artifact_path: None,
            initial_comparators: Vec::new(),
            skip_numeric_budget: false,
        });
        self.notes.push(format!("Refused: {}", reason.into()));
    }
    pub fn fill_missing_subjects(
        &mut self,
        workload_ref: &str,
        workload_desc: &str,
        op_mix: OpMix,
    ) {
        for s in REQUIRED_SUBJECTS {
            if !self.entries.iter().any(|e| e.subject == *s) {
                self.record_refused(
                    *s,
                    workload_ref,
                    workload_desc,
                    op_mix,
                    ValidationTier::QemuGuest,
                    format!("no runtime harness for {s}"),
                );
            }
        }
    }
    /// Run comparators declared by ComparatorManifest for every live-runtime
    /// subject already recorded in this runner.  Captured comparator refs are
    /// added to the matching entry; staged/unavailable comparators go to
    /// comparator_entries with blocker notes.
    pub fn run_comparators(&mut self, harness: &ComparatorHarness) {
        // Collect the subset of subjects that need comparators
        let subjects: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.validation_tier.is_live_runtime())
            .map(|e| e.subject.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();

        for subject in &subjects {
            let kinds = ComparatorManifest::comparators_for(subject);
            let runs = harness.run_all(subject, &kinds);
            for run in runs {
                // Add ComparatorRef to matching entry
                if let Some(entry) = self
                    .entries
                    .iter_mut()
                    .find(|e| e.subject == *subject && e.validation_tier.is_live_runtime())
                {
                    entry.comparators.push(run.to_comparator_ref());
                }
                // Track all runs in receipt
                self.comparator_entries.push(run.clone());
                if let Some(ref blocker) = run.blocker {
                    self.notes
                        .push(format!("{}: {} — {}", subject, run.ref_id, blocker));
                }
            }
        }

        // Re-apply artifact enforcement since comparators were just added
        for entry in &mut self.entries {
            if entry.validation_tier.is_live_runtime() {
                entry.enforce_artifact_requirements();
            }
        }
    }

    /// Evaluate multi-node degradation budget by comparing single-node
    /// baseline KPIs against multi-node runtime KPIs.
    ///
    /// If multi-node KPIs are empty (no runtime validation), stores a Refuse
    /// summary indicating the missing validation.
    pub fn evaluate_degradation(
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
        self.degradation = Some(DegradationSummary {
            evaluated: true,
            decision: format!("{:?}", comparison.decision),
            buckets,
            single_node_kpi_count: comparison.single_node_kpis.len(),
            multi_node_kpi_count: comparison.multi_node_kpis.len(),
            summary: comparison.summary_line(),
        });
    }

    /// Evaluate degradation from entries with explicit subject naming:
    /// entries whose subject starts with "single-node-" provide baselines,
    /// entries whose subject starts with "multi-node-" provide measurements.
    pub fn evaluate_degradation_from_entries(&mut self) {
        let sn_kpis: Vec<MeasuredKpi> = self
            .entries
            .iter()
            .filter(|e| e.subject.starts_with("single-node-"))
            .flat_map(|e| e.kpis.clone())
            .collect();
        let mn_kpis: Vec<MeasuredKpi> = self
            .entries
            .iter()
            .filter(|e| e.subject.starts_with("multi-node-"))
            .flat_map(|e| e.kpis.clone())
            .collect();
        self.evaluate_degradation(
            sn_kpis,
            mn_kpis,
            MultiNodeDegradationBudget::release_standard(),
        );
    }

    pub fn finalize(self) -> GateReceipt {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let ts = iso8601_from_epoch(now.as_secs());
        let mut m = PerformanceMatrix::new(&self.commit_sha, &ts);
        for e in &self.entries {
            m.add_row(e.clone());
        }
        let s = m.summary();
        let ms: Vec<String> = m
            .missing_required_subjects()
            .into_iter()
            .map(|s| s.to_string())
            .collect();
        let ih = ms.is_empty();
        let artifact_gap = s.artifact_gap;
        let budget_gap = s.budget_gap;
        let perf_gate_ready =
            m.has_runtime_validation() && ih && artifact_gap == 0 && budget_gap == 0;
        let rows: Vec<GateReceiptRow> = self
            .entries
            .iter()
            .map(|e| {
                let v = match e.status {
                    RowStatus::Pass => RunVerdict::Passed,
                    RowStatus::Fail => RunVerdict::Failed,
                    RowStatus::Refuse => RunVerdict::Refused,
                    RowStatus::Pending => RunVerdict::Skipped,
                };
                GateReceiptRow {
                    subject: e.subject.clone(),
                    workload_ref: e.workload.ref_id.clone(),
                    environment_ref: e.environment.profile_ref.clone(),
                    validation_tier: e.validation_tier.label().to_string(),
                    verdict: v,
                    budget_decision: e.budget_decision,
                    kpis: e.kpis.clone(),
                    artifact_path: e.artifact_path.clone(),
                    artifacts_satisfied: e.artifacts_satisfied(),
                    budget_buckets: e
                        .budget_buckets
                        .iter()
                        .map(|b| b.label().to_string())
                        .collect(),
                }
            })
            .collect();
        GateReceipt {
            matrix_ref: PerformanceMatrix::MATRIX_REF.into(),
            commit_sha: self.commit_sha.clone(),
            generated_at: ts,
            rows,
            comparator_runs: self.comparator_entries.clone(),
            summary: ReceiptSummary {
                total: s.total_rows,
                passed: s.pass,
                failed: s.fail,
                refused: s.refuse,
                skipped: s.pending,
                runtime_pass: s.runtime_pass,
                code_only_pass: s.code_only_pass,
                artifact_gap: s.artifact_gap,
                budget_gap: self
                    .entries
                    .iter()
                    .filter(|e| !e.budget_buckets.is_empty())
                    .count(),
            },
            perf_gate_ready,
            invariant_holds: ih,
            missing_subjects: ms,
            notes: self.notes,
            artifact_path: None,
            degradation_summary: self.degradation,
        }
    }
    pub fn build_current_head_with_benches(
        commit_sha: impl Into<String>,
        env: EnvironmentManifest,
        repo_root: &str,
        target_dir: &str,
    ) -> GateReceipt {
        let mut r = GateRunner::new(env, commit_sha.into());
        let om = OpMix {
            read_pct: 70,
            write_pct: 20,
            metadata_pct: 5,
            sync_pct: 5,
            concurrency: 4,
        };
        r.record_benchmark(
            &super::fuse_fio_harness::FuseFioHarness::new(repo_root).run_smoke(),
            "env.e1",
            "fuse",
            om,
        );
        // Multi-node transport budget measurement (REL-MN-011).
        let transport_om = OpMix {
            read_pct: 50,
            write_pct: 50,
            metadata_pct: 0,
            sync_pct: 0,
            concurrency: 1,
        };
        r.record_benchmark(
            &super::transport_harness::TransportHarness::new(repo_root, target_dir).run(),
            "env.e1",
            "two-node harness transport budget",
            transport_om,
        );
        // RDMA vs TCP carrier performance comparison.
        let carrier_report =
            carrier_comparison::compare_carriers(repo_root, target_dir, &r.commit_sha, None);
        let carrier_om = OpMix {
            read_pct: 50,
            write_pct: 50,
            metadata_pct: 0,
            sync_pct: 0,
            concurrency: 1,
        };
        let carrier_result =
            carrier_comparison_to_benchmark_result(&carrier_report, "carrier-comparison");
        r.record_benchmark(
            &carrier_result,
            "env.e1",
            "RDMA vs TCP carrier performance comparison",
            carrier_om,
        );
        // ublk queue-depth latency budget measurement.
        let ublk_om = OpMix {
            read_pct: 70,
            write_pct: 30,
            metadata_pct: 0,
            sync_pct: 0,
            concurrency: 1,
        };
        r.record_benchmark(
            &super::benchmark_harness::UblkFioHarness::new("/dev/ublkb0").run("ublk-direct"),
            "env.e1",
            "ublk queue-depth latency budget",
            ublk_om,
        );
        // Metadata workload baseline.
        let metadata_om = OpMix {
            read_pct: 0,
            write_pct: 0,
            metadata_pct: 100,
            sync_pct: 0,
            concurrency: 1,
        };
        let meta_path = format!("{}/tidefs-meta-gate-tmp", std::env::temp_dir().display());
        r.record_benchmark(
            &super::metadata_harness::MetadataHarness::new(repo_root).run_smoke(&meta_path),
            "env.e1",
            "metadata create/stat/rename/unlink workload baseline",
            metadata_om,
        );
        let _ = std::fs::remove_dir_all(&meta_path);
        r.fill_missing_subjects("env.e1", "pending", om);
        // Run comparators for live-runtime subjects (ext4, raw-block, staged)
        let ch = ComparatorHarness::new(repo_root);
        r.run_comparators(&ch);
        r.finalize()
    }

    /// Attach a comparator ref to every entry whose subject matches one of the
    /// given subject names. Used by baseline-package loading so external
    /// baseline KPIs feed into budget evaluation and regression locks.
    pub fn set_comparator_for(&mut self, subjects: &[&str], comp: ComparatorRef) {
        for entry in &mut self.entries {
            if subjects.contains(&entry.subject.as_str()) {
                if !entry.comparators.iter().any(|c| c.ref_id == comp.ref_id) {
                    entry.comparators.push(comp.clone());
                    entry.evaluate_budget();
                }
            }
        }
        for entry in &mut self.entries {
            entry.enforce_artifact_requirements();
        }
    }

    /// Build a receipt from an external baseline package directory.
    ///
    /// Loads external baseline outputs and maps their KPIs into
    /// performance gate entries with comparator refs.  Budget evaluation and
    /// output enforcement is applied, so the resulting receipt fails when
    /// comparator outputs, KPIs, noise profiles, or budgets are missing or
    /// violated.
    pub fn build_from_baseline_package(
        commit_sha: impl Into<String>,
        env: EnvironmentManifest,
        package_path: &str,
    ) -> GateReceipt {
        super::baseline_package::build_receipt_from_baseline(package_path, &commit_sha.into(), &env)
    }

    /// Build a receipt from an external baseline package (comparator source)
    /// and a separate current-run manifest (live measurements).
    ///
    /// The baseline package provides comparator refs and budget definitions.
    /// The current-run manifest provides live KPIs measured on the current
    /// code.  The gate evaluates whether current measurements regress against
    /// approved baselines and whether numeric budgets are violated.
    pub fn build_from_baseline_and_current(
        commit_sha: impl Into<String>,
        env: EnvironmentManifest,
        package_path: &str,
        current_run_path: &str,
    ) -> GateReceipt {
        super::baseline_package::build_receipt_from_baseline_and_current(
            package_path,
            current_run_path,
            &commit_sha.into(),
            &env,
        )
    }

    pub fn build_current_head_receipt(
        commit_sha: impl Into<String>,
        env: EnvironmentManifest,
    ) -> GateReceipt {
        let mut r = GateRunner::new(env, commit_sha.into());
        let om = OpMix {
            read_pct: 70,
            write_pct: 20,
            metadata_pct: 5,
            sync_pct: 5,
            concurrency: 4,
        };
        r.fill_missing_subjects("env.e1", "pending", om);
        r.note("all rows refused pending harness wiring");
        r.finalize()
    }
}

fn iso8601_from_epoch(secs: u64) -> String {
    let ds = secs % 86400;
    let days = secs / 86400;
    let mut y = 1970i64;
    let mut rem = days as i64;
    loop {
        let diy = if is_leap(y) { 366 } else { 365 };
        if rem < diy {
            break;
        }
        rem -= diy;
        y += 1;
    }
    let md = if is_leap(y) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut mo = 0;
    for (i, &d) in md.iter().enumerate() {
        if rem < d as i64 {
            mo = i + 1;
            break;
        }
        rem -= d as i64;
        if i == 11 {
            mo = 12;
            break;
        }
    }
    let d = rem + 1;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        mo,
        d,
        ds / 3600,
        (ds % 3600) / 60,
        ds % 60
    )
}
fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)
}

/// Convert a CarrierComparisonReport into a BenchmarkResult for the performance gate matrix.
fn carrier_comparison_to_benchmark_result(
    report: &CarrierComparisonReport,
    subject: &str,
) -> BenchmarkResult {
    use super::validation_tier::ValidationTier;
    let tier = ValidationTier::MultiProcessDistributed;
    let executed = !report.loopback_baseline.is_empty();
    let mut kpis = Vec::new();
    for m in &report.loopback_baseline {
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.latency.{}.{}B", subject, m.payload_size_bytes),
            name: format!("{}/latency-us-{}B", subject, m.payload_size_bytes),
            value: m.avg_latency_us,
            unit: "us".into(),
            passed: None,
            percentile: None,
        });
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.throughput.{}.{}B", subject, m.payload_size_bytes),
            name: format!("{}/throughput-mb_s-{}B", subject, m.payload_size_bytes),
            value: m.throughput_mb_s,
            unit: "MB/s".into(),
            passed: None,
            percentile: None,
        });
    }
    // Add carrier disclosure as KPI notes
    kpis.push(MeasuredKpi {
        ref_id: format!("kpi.{subject}.carrier-mode"),
        name: format!("{subject}/carrier-mode"),
        value: 0.0,
        unit: format!(
            "rdma_available={} rdma_link_active={} tcp_available={} fallback={}",
            report.probe.rdma_available,
            report.probe.rdma_link_active,
            report.probe.tcp_available,
            report.probe.fallback,
        ),
        passed: None,
        percentile: None,
    });
    let desc = if executed {
        format!(
            "carrier comparison: {} loopback measurements, verdict {:?}, rdma={} tcp={}",
            report.loopback_baseline.len(),
            report.verdict,
            report.probe.rdma_available,
            report.probe.tcp_available,
        )
    } else {
        "carrier comparison: loopback baseline not executed".to_string()
    };
    BenchmarkResult {
        subject: subject.to_string(),
        description: desc,
        executed,
        exit_code: if executed { Some(0) } else { None },
        duration_secs: report
            .loopback_baseline
            .iter()
            .map(|m| m.avg_latency_us / 1_000_000.0)
            .sum(),
        kpis,
        validation_tier: tier,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::performance_gate::NoisePolicy;
    fn se() -> EnvironmentManifest {
        EnvironmentManifest {
            profile_ref: "e2".into(),
            host_class: "vm".into(),
            cpu_count: 4,
            memory_bytes: 8_589_934_592,
            kernel_version: "L7".into(),
            storage_backend: "los".into(),
            cache_mode: "none".into(),
            feature_flags: vec![],
            background_load: None,
            noise_policy: NoisePolicy {
                ref_id: "n".into(),
                warmup_samples: 5,
                min_samples: 30,
                max_cv: 0.05,
            },
        }
    }
    fn so() -> OpMix {
        OpMix {
            read_pct: 70,
            write_pct: 20,
            metadata_pct: 5,
            sync_pct: 5,
            concurrency: 4,
        }
    }
    #[test]
    fn record_finalize() {
        let mut r = GateRunner::new(se(), "abc");
        r.record(GateRunRecord {
            subject: "fs".into(),
            workload_ref: "e1".into(),
            workload_desc: "rw".into(),
            op_mix: so(),
            validation_tier: ValidationTier::QemuGuest,
            budget_classes: vec![],
            verdict: RunVerdict::Refused,
            kpis: vec![],
            artifact_path: None,
            initial_comparators: Vec::new(),
            skip_numeric_budget: false,
        });
        assert!(r.finalize().rows.iter().any(|x| x.subject == "fs"));
    }
    #[test]
    fn fill() {
        let mut r = GateRunner::new(se(), "abc");
        r.fill_missing_subjects("e1", "t", so());
        let rec = r.finalize();
        assert!(rec.invariant_holds);
        assert_eq!(rec.summary.refused, REQUIRED_SUBJECTS.len());
    }
    #[test]
    fn receipt() {
        let rec = GateRunner::build_current_head_receipt("d", se());
        assert!(rec.invariant_holds);
        assert_eq!(rec.summary.refused, REQUIRED_SUBJECTS.len());
        assert!(rec.render_markdown().contains("Performance gate: NOT READY"));
    }
    #[test]
    fn notes() {
        let mut r = GateRunner::new(se(), "abc");
        r.note("n");
        assert_eq!(r.finalize().notes.len(), 1);
    }
    #[test]
    fn iso() {
        assert_eq!(iso8601_from_epoch(1715904000), "2024-05-17T00:00:00Z");
    }
    #[test]
    fn bench_refused() {
        let mut r = GateRunner::new(se(), "abc");
        r.record_benchmark(
            &BenchmarkResult::refused("t", "r", ValidationTier::QemuGuest),
            "e1",
            "d",
            so(),
        );
        assert_eq!(
            r.finalize()
                .rows
                .iter()
                .find(|x| x.subject == "t")
                .unwrap()
                .verdict,
            RunVerdict::Refused
        );
    }
    #[test]
    fn benches_complete() {
        assert!(
            GateRunner::build_current_head_with_benches(
                "abc",
                se(),
                "/nonexistent",
                "/tmp/does-not-exist"
            )
            .invariant_holds
        );
    }
}
