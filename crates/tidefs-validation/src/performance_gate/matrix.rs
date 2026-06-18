// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use super::gate_entry::{PerformanceGateEntry, RowStatus};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PerformanceMatrix {
    pub rows: Vec<PerformanceGateEntry>,
    pub commit_sha: String,
    pub generated_at: String,
    pub matrix_ref: String,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixSummary {
    pub total_rows: usize,
    pub pass: usize,
    pub fail: usize,
    pub refuse: usize,
    pub pending: usize,
    pub code_only_pass: usize,
    pub runtime_pass: usize,
    pub code_only_gap: usize,
    pub artifact_gap: usize,
    pub budget_gap: usize,
}

impl PerformanceMatrix {
    pub const MATRIX_REF: &'static str = "matrix.performance.budget.performance_budget_0";
    pub fn new(commit_sha: impl Into<String>, generated_at: impl Into<String>) -> Self {
        PerformanceMatrix {
            rows: Vec::new(),
            commit_sha: commit_sha.into(),
            generated_at: generated_at.into(),
            matrix_ref: Self::MATRIX_REF.into(),
        }
    }
    pub fn add_row(&mut self, entry: PerformanceGateEntry) {
        self.rows.push(entry);
    }
    pub fn rows_for_subject(&self, subject: &str) -> Vec<&PerformanceGateEntry> {
        self.rows.iter().filter(|r| r.subject == subject).collect()
    }
    pub fn summary(&self) -> MatrixSummary {
        let total = self.rows.len();
        let pass_all = self
            .rows
            .iter()
            .filter(|r| r.status == RowStatus::Pass)
            .count();
        let runtime_pass = self
            .rows
            .iter()
            .filter(|r| r.is_release_validation())
            .count();
        let code_only_pass = pass_all.saturating_sub(runtime_pass);
        let fail = self
            .rows
            .iter()
            .filter(|r| r.status == RowStatus::Fail)
            .count();
        let refuse = self
            .rows
            .iter()
            .filter(|r| r.status == RowStatus::Refuse)
            .count();
        let pending = self
            .rows
            .iter()
            .filter(|r| r.status == RowStatus::Pending)
            .count();
        let code_only_gap = self
            .rows
            .iter()
            .filter(|r| r.validation_tier.is_code_only() && r.status != RowStatus::Pass)
            .count();
        // Rows at live-runtime tiers that are PASS but fail artifact requirements
        // (they should have been downgraded to Refuse by enforce_artifact_requirements)
        let artifact_gap = self
            .rows
            .iter()
            .filter(|r| r.validation_tier.is_live_runtime() && !r.artifacts_satisfied())
            .count();
        // Rows with open budget buckets (data gaps or violations)
        let budget_gap = self
            .rows
            .iter()
            .filter(|r| !r.budget_buckets.is_empty())
            .count();
        MatrixSummary {
            total_rows: total,
            pass: pass_all,
            fail,
            refuse,
            pending,
            code_only_pass,
            runtime_pass,
            code_only_gap,
            artifact_gap,
            budget_gap,
        }
    }
    /// True when at least one row has live-runtime measured validation.
    /// Subject-completeness alone (invariant_holds) is insufficient for
    /// release readiness.
    pub fn has_runtime_validation(&self) -> bool {
        self.rows.iter().any(|r| r.is_release_validation())
    }
    pub fn missing_required_subjects(&self) -> Vec<&'static str> {
        REQUIRED_SUBJECTS
            .iter()
            .filter(|s| !self.rows.iter().any(|r| r.subject == **s))
            .copied()
            .collect()
    }
    pub fn invariant_holds(&self) -> bool {
        self.missing_required_subjects().is_empty()
    }
    pub fn render_markdown(&self) -> String {
        let s = self.summary();
        let m = self.missing_required_subjects();
        let mut o=format!("# Performance Budget Gate — {}\n\nCommit: `{}` | Generated: {}\n\n## Summary\n\n| Metric | Count |\n|--------|-------|\n| Total rows | {} |\n| Pass (runtime) | {} |\n| Pass (code-only) | {} |\n| Fail | {} |\n| Refuse | {} |\n| Pending | {} |\n| Artifact gap | {} |\n| Budget gap | {} |\n",self.matrix_ref,self.commit_sha,self.generated_at,s.total_rows,s.runtime_pass,s.code_only_pass,s.fail,s.refuse,s.pending,s.artifact_gap,s.budget_gap);
        if !m.is_empty() {
            o.push_str("\n### Missing\n\n");
            for x in &m {
                o.push_str(&format!("- `{x}`\n"));
            }
        }
        o.push_str("\n## Rows\n\n| Subject | Workload | Environment | Tier | Source | Budget | Artifacts | Buckets | Status |\n|---------|----------|-------------|------|--------|--------|-----------|---------|--------|\n");
        for r in &self.rows {
            let source = match r.measurement_source {
                super::MeasurementSource::Measured => "measured",
                super::MeasurementSource::SchemaOnly => "schema",
            };
            let artifacts = if r.validation_tier.is_code_only() {
                "\u{2014}"
            } else if r.artifacts_satisfied() {
                "ok"
            } else {
                "gap"
            };
            let buckets = if r.budget_buckets.is_empty() {
                "\u{2014}".to_string()
            } else {
                r.budget_buckets
                    .iter()
                    .map(|b| b.label())
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            let budget = match r.status {
                RowStatus::Pass if r.validation_tier.is_code_only() => "pass\u{2020}",
                RowStatus::Pass => "pass",
                RowStatus::Fail => "fail",
                RowStatus::Refuse => "refuse",
                RowStatus::Pending => "pending",
            };
            o.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
                r.subject,
                r.workload.ref_id,
                r.environment.profile_ref,
                r.validation_tier.label(),
                source,
                budget,
                artifacts,
                buckets,
                match r.status {
                    RowStatus::Pass => "PASS",
                    RowStatus::Fail => "FAIL",
                    RowStatus::Refuse => "REFUSE",
                    RowStatus::Pending => "PENDING",
                }
            ));
        }
        o
    }
}

pub const REQUIRED_SUBJECTS: &[&str] = &[
    "local-object-store",
    "local-filesystem",
    "mounted-fuse",
    "ublk-direct",
    "ublk-ext4",
    "transport",
    "recovery-rebuild",
    "kernel-kmod-vfs",
    "kernel-block-kmod",
];

#[cfg(test)]
mod tests {
    use super::super::gate_entry::{NoisePolicy, OpMix, PendingPerformanceGateEntry};
    use super::*;
    use crate::performance_gate::{MeasurementSource, ValidationTier};
    fn me(
        s: &str,
        st: RowStatus,
        t: ValidationTier,
        ms: MeasurementSource,
    ) -> PerformanceGateEntry {
        let np = NoisePolicy {
            ref_id: "n".into(),
            warmup_samples: 5,
            min_samples: 30,
            max_cv: 0.05,
        };
        let mut e = PerformanceGateEntry::pending(PendingPerformanceGateEntry {
            subject: s.into(),
            workload_ref: "e1".into(),
            workload_desc: "rw".into(),
            op_mix: OpMix {
                read_pct: 70,
                write_pct: 20,
                metadata_pct: 5,
                sync_pct: 5,
                concurrency: 4,
            },
            env_profile_ref: "e2".into(),
            host_class: "h".into(),
            cpu_count: 4,
            memory_bytes: 8_589_934_592,
            kernel_version: "L7".into(),
            storage_backend: "nvme".into(),
            cache_mode: "none".into(),
            noise_policy: np,
            validation_tier: t,
            budget_classes: vec![],
            commit_sha: "abc".into(),
        });
        e.status = st;
        e.measurement_source = ms;
        e
    }
    #[test]
    fn empty() {
        assert_eq!(PerformanceMatrix::new("a", "2026").summary().total_rows, 0);
    }
    #[test]
    fn summary_counts() {
        let mut m = PerformanceMatrix::new("a", "2026");
        m.add_row(me(
            "fs",
            RowStatus::Pass,
            ValidationTier::MountedUserspace,
            MeasurementSource::Measured,
        ));
        m.add_row(me(
            "fuse",
            RowStatus::Fail,
            ValidationTier::MountedUserspace,
            MeasurementSource::SchemaOnly,
        ));
        m.add_row(me(
            "tpt",
            RowStatus::Refuse,
            ValidationTier::QemuGuest,
            MeasurementSource::SchemaOnly,
        ));
        let s = m.summary();
        assert_eq!(s.pass, 1);
        assert_eq!(s.fail, 1);
        assert_eq!(s.refuse, 1);
    }
    #[test]
    fn missing() {
        let mut m = PerformanceMatrix::new("a", "2026");
        m.add_row(me(
            "fs",
            RowStatus::Pass,
            ValidationTier::MountedUserspace,
            MeasurementSource::Measured,
        ));
        assert!(!m.invariant_holds());
    }
    #[test]
    fn full() {
        let mut m = PerformanceMatrix::new("a", "2026");
        for s in REQUIRED_SUBJECTS {
            m.add_row(me(
                s,
                RowStatus::Refuse,
                ValidationTier::QemuGuest,
                MeasurementSource::SchemaOnly,
            ));
        }
        assert!(m.invariant_holds());
    }
    #[test]
    fn md() {
        let mut m = PerformanceMatrix::new("abc", "2026T");
        m.add_row(me(
            "fs",
            RowStatus::Pass,
            ValidationTier::MountedUserspace,
            MeasurementSource::Measured,
        ));
        assert!(m.render_markdown().contains("abc"));
    }
}
