// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Linux 7.0 kernel validation matrix for xfstests, fio, mkfs, and QEMU.
//!
//! # Runtime artifact source guard
//!
//! `KernelRowScoreboard::is_clean_pass()` requires a non-empty command and a
//! recorded kernel version.  A row without a real command or kernel version
//! is never a clean pass.  Use `is_genuine_runtime_pass()` for live-runtime
//! tiers; it additionally requires a concrete `RuntimeArtifactSource`.

#![deny(dead_code)]
#![deny(unused_imports)]

use crate::runtime_artifact_source::RuntimeArtifactSource;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelTestTarget {
    VfsCleanRead,
    VfsWriteback,
    BlockExport,
    BlockFull,
}

impl KernelTestTarget {
    pub fn label(&self) -> &'static str {
        match self {
            KernelTestTarget::VfsCleanRead => "vfs-clean-read",
            KernelTestTarget::VfsWriteback => "vfs-writeback",
            KernelTestTarget::BlockExport => "block-export",
            KernelTestTarget::BlockFull => "block-full",
        }
    }
    pub fn module_family(&self) -> &'static str {
        match self {
            KernelTestTarget::VfsCleanRead | KernelTestTarget::VfsWriteback => {
                "kmod.posix_filesystem_adapter.vfs.k0"
            }
            KernelTestTarget::BlockExport | KernelTestTarget::BlockFull => {
                "kmod.block_volume_adapter.block.k0"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelSuiteFamily {
    Xfstests,
    Fio,
    Mkfs,
    QemuSmoke,
}

impl KernelSuiteFamily {
    pub fn label(&self) -> &'static str {
        match self {
            KernelSuiteFamily::Xfstests => "xfstests",
            KernelSuiteFamily::Fio => "fio",
            KernelSuiteFamily::Mkfs => "mkfs",
            KernelSuiteFamily::QemuSmoke => "qemu-smoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequiredValidation {
    pub e1_charter: bool,
    pub e2_publication: bool,
    pub e6_operator_truth: bool,
}

impl Default for RequiredValidation {
    fn default() -> Self {
        RequiredValidation {
            e1_charter: true,
            e2_publication: true,
            e6_operator_truth: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelVariant {
    QemuGuest,
    HostKernel,
    NixosTest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelMatrixRow {
    pub row_id: String,
    pub target: KernelTestTarget,
    pub suite: KernelSuiteFamily,
    pub variant: KernelVariant,
    pub description: String,
    pub required_validation: RequiredValidation,
    pub test_filter: String,
    pub executable: bool,
}

impl KernelMatrixRow {
    pub fn new(
        row_id: impl Into<String>,
        target: KernelTestTarget,
        suite: KernelSuiteFamily,
        variant: KernelVariant,
        description: impl Into<String>,
        test_filter: impl Into<String>,
    ) -> Self {
        KernelMatrixRow {
            row_id: row_id.into(),
            target,
            suite,
            variant,
            description: description.into(),
            required_validation: RequiredValidation::default(),
            test_filter: test_filter.into(),
            executable: false,
        }
    }
}

// ---------------------------------------------------------------------------
// Five-way validation classification (REL-VAL-006)
// ---------------------------------------------------------------------------

/// Unified outcome for a single kernel test result.
///
/// Distinguishes product failures from harness failures so release validation
/// never conflates them. Mirrors `crate::validation_status::ValidationStatus`
/// with kernel-validation-specific serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KernelTestStatus {
    /// Product behaved correctly; harness recorded clean execution.
    Pass,
    /// TideFS kernel code is defective (wrong data, crash, hang, contract violation).
    ProductFail,
    /// Harness/tooling/script is defective, not the product.
    HarnessFail,
    /// Environment refused the workload (missing /dev/fuse, /dev/kvm, kernel
    /// module not loaded, RDMA device absent, etc.). Not a product defect.
    EnvironmentRefusal,
    /// Intentionally not exercised for this tier/run.
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelTestResult {
    pub test_name: String,
    pub status: KernelTestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_secs: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelRowScoreboard {
    pub row_id: String,
    pub started_at: String,
    pub duration_secs: f64,
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    pub results: Vec<KernelTestResult>,
    pub summary: KernelRowSummary,
    /// Concrete artifact source required for live-runtime tier Pass
    /// classification.  None for schema-level or non-exercised rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_source: Option<RuntimeArtifactSource>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelRowSummary {
    pub total: usize,
    pub passed: usize,
    /// Product failures: TideFS code is defective.
    pub product_failures: usize,
    /// Harness failures: test infrastructure is defective.
    pub harness_failures: usize,
    pub skipped: usize,
    pub refusals: usize,
}

impl KernelRowSummary {
    /// Total failures of any kind (product + harness).
    pub fn total_failures(&self) -> usize {
        self.product_failures + self.harness_failures
    }
}

impl KernelRowScoreboard {
    /// Clean pass requires: a non-empty command was issued, a kernel
    /// version is recorded, and zero product/harness failures and zero refusals.
    ///
    /// Rows with empty command or missing kernel version are schema
    /// placeholders, not runtime validation.
    pub fn is_clean_pass(&self) -> bool {
        !self.command.is_empty()
            && self.kernel_version.is_some()
            && self.summary.product_failures == 0
            && self.summary.harness_failures == 0
            && self.summary.refusals == 0
    }

    pub fn is_refusal_only(&self) -> bool {
        self.summary.product_failures == 0
            && self.summary.harness_failures == 0
            && self.summary.refusals > 0
    }

    pub fn has_product_failures(&self) -> bool {
        self.summary.product_failures > 0
    }

    pub fn has_harness_failures(&self) -> bool {
        self.summary.harness_failures > 0
    }

    /// True when this scoreboard represents a genuine runtime pass:
    /// clean pass + command executed + kernel version recorded + artifact attached.
    pub fn is_genuine_runtime_pass(&self) -> bool {
        self.is_clean_pass()
            && self
                .artifact_source
                .as_ref()
                .map(|a| a.is_genuine())
                .unwrap_or(false)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelMatrixSummary {
    pub started_at: String,
    pub duration_secs: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_commit: Option<String>,
    #[serde(default)]
    pub repo_dirty: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    pub rows: Vec<KernelRowScoreboard>,
    pub gate: KernelGateReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelGateReceipt {
    pub total_rows: usize,
    pub passed_rows: usize,
    pub product_fail_rows: usize,
    pub harness_fail_rows: usize,
    pub refused_rows: usize,
    pub skipped_rows: usize,
    pub gate_passed: bool,
    pub verdict: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelValidationMatrix {
    pub family: String,
    pub description: String,
    pub rows: Vec<KernelMatrixRow>,
}

impl Default for KernelValidationMatrix {
    fn default() -> Self {
        KernelValidationMatrix {
            family: "matrix.kernel_validation.k7_10".into(),
            description:
                "Linux 7.0 full kernel validation matrix for xfstests, fio, mkfs, and QEMU".into(),
            rows: default_matrix_rows(),
        }
    }
}

pub fn default_matrix_rows() -> Vec<KernelMatrixRow> {
    vec![
        KernelMatrixRow::new(
            "k7-10-vfs-cleanread-xfstests-generic",
            KernelTestTarget::VfsCleanRead,
            KernelSuiteFamily::Xfstests,
            KernelVariant::QemuGuest,
            "xfstests generic/001-050 quick group against VFS clean-read kmod",
            "generic/001-050",
        ),
        KernelMatrixRow::new(
            "k7-10-vfs-cleanread-xfstests-lock",
            KernelTestTarget::VfsCleanRead,
            KernelSuiteFamily::Xfstests,
            KernelVariant::QemuGuest,
            "xfstests lock/symlink/fallocate against VFS clean-read kmod",
            "lock,symlink,fallocate",
        ),
        KernelMatrixRow::new(
            "k7-10-vfs-cleanread-fio",
            KernelTestTarget::VfsCleanRead,
            KernelSuiteFamily::Fio,
            KernelVariant::QemuGuest,
            "fio data-integrity against VFS-mounted fs via kernel kmod",
            "seq-write,seq-read,rand-write,rand-read",
        ),
        KernelMatrixRow::new(
            "k7-10-vfs-cleanread-qemu-smoke",
            KernelTestTarget::VfsCleanRead,
            KernelSuiteFamily::QemuSmoke,
            KernelVariant::QemuGuest,
            "QEMU boot with VFS kmod loaded, smoke-mount passes",
            "smoke-mount",
        ),
        KernelMatrixRow::new(
            "k7-10-vfs-writeback-xfstests-generic",
            KernelTestTarget::VfsWriteback,
            KernelSuiteFamily::Xfstests,
            KernelVariant::QemuGuest,
            "xfstests generic/001-050 against VFS writeback kmod",
            "generic/001-050",
        ),
        KernelMatrixRow::new(
            "k7-10-vfs-writeback-fio-fsync",
            KernelTestTarget::VfsWriteback,
            KernelSuiteFamily::Fio,
            KernelVariant::QemuGuest,
            "fio fsync against VFS writeback kmod",
            "fsync-write,fsync-read,mixed-rw",
        ),
        KernelMatrixRow::new(
            "k7-10-block-export-fio",
            KernelTestTarget::BlockExport,
            KernelSuiteFamily::Fio,
            KernelVariant::QemuGuest,
            "fio direct-I/O against block kmod fixed-capacity export",
            "seq-write,seq-read,rand-write,rand-read,mixed-rw",
        ),
        KernelMatrixRow::new(
            "k7-10-block-export-mkfs",
            KernelTestTarget::BlockExport,
            KernelSuiteFamily::Mkfs,
            KernelVariant::QemuGuest,
            "ext4 mkfs/mount/write/read/unmount on block kmod export",
            "ext4-mkfs-mount",
        ),
        KernelMatrixRow::new(
            "k7-10-block-export-qemu-smoke",
            KernelTestTarget::BlockExport,
            KernelSuiteFamily::QemuSmoke,
            KernelVariant::QemuGuest,
            "QEMU boot with block kmod loaded, ublk device visible",
            "device-visible",
        ),
        KernelMatrixRow::new(
            "k7-10-block-full-fio-flush",
            KernelTestTarget::BlockFull,
            KernelSuiteFamily::Fio,
            KernelVariant::QemuGuest,
            "fio flush/FUA against block kmod full export",
            "fsync-write,fsync-read",
        ),
        KernelMatrixRow::new(
            "k7-10-block-full-fio-trim",
            KernelTestTarget::BlockFull,
            KernelSuiteFamily::Fio,
            KernelVariant::QemuGuest,
            "fio trim/discard against block kmod full export",
            "trim-write,trim-discard,trim-read",
        ),
    ]
}

pub trait KernelMatrixRunner {
    fn run_row(&self, row: &KernelMatrixRow) -> KernelRowScoreboard;

    fn run_matrix(&self, matrix: &KernelValidationMatrix) -> KernelMatrixSummary {
        let started_at = chrono_now();
        let start = std::time::Instant::now();
        let mut rows = Vec::new();
        for row in &matrix.rows {
            if row.executable {
                rows.push(self.run_row(row));
            } else {
                rows.push(KernelRowScoreboard {
                    row_id: row.row_id.clone(),
                    started_at: started_at.clone(),
                    duration_secs: 0.0,
                    command: String::new(),
                    kernel_version: None,
                    results: Vec::new(),
                    artifact_source: None,
                    summary: KernelRowSummary {
                        total: 1,
                        passed: 0,
                        product_failures: 0,
                        harness_failures: 0,
                        skipped: 0,
                        refusals: 1,
                    },
                });
            }
        }
        let duration_secs = start.elapsed().as_secs_f64();
        let total_rows = rows.len();
        let passed_rows = rows.iter().filter(|r| r.is_clean_pass()).count();
        let product_fail_rows = rows.iter().filter(|r| r.has_product_failures()).count();
        let harness_fail_rows = rows.iter().filter(|r| r.has_harness_failures()).count();
        let refused_rows = rows
            .iter()
            .filter(|r| r.summary.total_failures() == 0 && r.summary.refusals > 0)
            .count();
        let skipped_rows =
            total_rows - passed_rows - product_fail_rows - harness_fail_rows - refused_rows;
        let gate_passed = product_fail_rows == 0
            && harness_fail_rows == 0
            && refused_rows == 0
            && passed_rows > 0;
        let verdict = if gate_passed {
            "gate passed: all rows executed and passed".into()
        } else if refused_rows > 0 && product_fail_rows == 0 && harness_fail_rows == 0 {
            format!(
                "gate refused: {refused_rows} rows could not execute (missing kernel modules or environment)"
            )
        } else if product_fail_rows > 0 || harness_fail_rows > 0 {
            format!(
                "gate failed: {product_fail_rows} product failures, {harness_fail_rows} harness failures, {refused_rows} rows refused"
            )
        } else {
            "gate skipped: no rows executed".into()
        };
        KernelMatrixSummary {
            started_at,
            duration_secs,
            repo_commit: None,
            repo_dirty: false,
            kernel_version: None,
            rows,
            gate: KernelGateReceipt {
                total_rows,
                passed_rows,
                product_fail_rows,
                harness_fail_rows,
                refused_rows,
                skipped_rows,
                gate_passed,
                verdict,
            },
        }
    }
}

fn chrono_now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("{}-01-01T00:00:00Z", 1970 + secs / 31556952)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matrix_has_rows() {
        let m = KernelValidationMatrix::default();
        assert!(!m.rows.is_empty());
        assert_eq!(m.family, "matrix.kernel_validation.k7_10");
    }

    #[test]
    fn rows_initially_non_executable() {
        for r in &default_matrix_rows() {
            assert!(!r.executable, "row {} not executable", r.row_id);
        }
    }

    #[test]
    fn unique_row_ids() {
        let rows_binding = default_matrix_rows();
        let mut ids: Vec<&str> = rows_binding.iter().map(|r| r.row_id.as_str()).collect();
        ids.sort();
        let n = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), n);
    }

    #[test]
    fn each_target_covered() {
        let targets: std::collections::HashSet<_> =
            default_matrix_rows().iter().map(|r| r.target).collect();
        assert!(targets.contains(&KernelTestTarget::VfsCleanRead));
        assert!(targets.contains(&KernelTestTarget::VfsWriteback));
        assert!(targets.contains(&KernelTestTarget::BlockExport));
        assert!(targets.contains(&KernelTestTarget::BlockFull));
    }

    #[test]
    fn each_suite_covered() {
        let suites: std::collections::HashSet<_> =
            default_matrix_rows().iter().map(|r| r.suite).collect();
        assert!(suites.contains(&KernelSuiteFamily::Xfstests));
        assert!(suites.contains(&KernelSuiteFamily::Fio));
        assert!(suites.contains(&KernelSuiteFamily::Mkfs));
        assert!(suites.contains(&KernelSuiteFamily::QemuSmoke));
    }

    #[test]
    fn labels() {
        assert_eq!(KernelTestTarget::VfsCleanRead.label(), "vfs-clean-read");
        assert_eq!(KernelTestTarget::BlockExport.label(), "block-export");
        assert_eq!(KernelSuiteFamily::Xfstests.label(), "xfstests");
        assert_eq!(KernelSuiteFamily::QemuSmoke.label(), "qemu-smoke");
    }

    #[test]
    fn module_families() {
        assert_eq!(
            KernelTestTarget::VfsCleanRead.module_family(),
            "kmod.posix_filesystem_adapter.vfs.k0"
        );
        assert_eq!(
            KernelTestTarget::BlockExport.module_family(),
            "kmod.block_volume_adapter.block.k0"
        );
    }

    #[test]
    fn clean_pass_requires_command_and_kernel_version() {
        let genuine = KernelRowScoreboard {
            row_id: "t".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "test-cmd".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 10,
                passed: 10,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(genuine.is_clean_pass());

        // Empty command => not clean pass
        let no_cmd = KernelRowScoreboard {
            row_id: "nc".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 10,
                passed: 10,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!no_cmd.is_clean_pass());

        // Missing kernel version => not clean pass
        let no_kver = KernelRowScoreboard {
            row_id: "nk".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "cmd".into(),
            kernel_version: None,
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 10,
                passed: 10,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!no_kver.is_clean_pass());

        // Product failures => not clean pass
        let prod_fail = KernelRowScoreboard {
            row_id: "pf".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "cmd".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 10,
                passed: 8,
                product_failures: 2,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!prod_fail.is_clean_pass());
        assert!(prod_fail.has_product_failures());
        assert!(!prod_fail.has_harness_failures());

        // Harness failures => not clean pass
        let harness_fail = KernelRowScoreboard {
            row_id: "hf".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "cmd".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 10,
                passed: 8,
                product_failures: 0,
                harness_failures: 2,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!harness_fail.is_clean_pass());
        assert!(!harness_fail.has_product_failures());
        assert!(harness_fail.has_harness_failures());
    }

    #[test]
    fn refusal_only() {
        let sb = KernelRowScoreboard {
            row_id: "t".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "".into(),
            kernel_version: None,
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 1,
                passed: 0,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 1,
            },
        };
        assert!(sb.is_refusal_only());
        // But not refusal-only if there are product failures
        let sb2 = KernelRowScoreboard {
            row_id: "t2".into(),
            started_at: "".into(),
            duration_secs: 0.0,
            command: "".into(),
            kernel_version: None,
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 2,
                passed: 0,
                product_failures: 1,
                harness_failures: 0,
                skipped: 0,
                refusals: 1,
            },
        };
        assert!(!sb2.is_refusal_only());
    }

    #[test]
    fn total_failures_sums_both_types() {
        let s = KernelRowSummary {
            total: 10,
            passed: 6,
            product_failures: 2,
            harness_failures: 1,
            skipped: 1,
            refusals: 0,
        };
        assert_eq!(s.total_failures(), 3);
    }

    #[test]
    fn kernel_test_status_serde_roundtrip() {
        let variants = [
            KernelTestStatus::Pass,
            KernelTestStatus::ProductFail,
            KernelTestStatus::HarnessFail,
            KernelTestStatus::EnvironmentRefusal,
            KernelTestStatus::Skip,
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: KernelTestStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back, "roundtrip failed for {v:?}");
        }
    }

    #[test]
    fn row_json_roundtrip() {
        let r = KernelMatrixRow::new(
            "test",
            KernelTestTarget::VfsCleanRead,
            KernelSuiteFamily::Xfstests,
            KernelVariant::QemuGuest,
            "desc",
            "all",
        );
        let j = serde_json::to_string(&r).unwrap();
        let d: KernelMatrixRow = serde_json::from_str(&j).unwrap();
        assert_eq!(d.row_id, "test");
    }

    #[test]
    fn scoreboard_json_roundtrip() {
        let sb = KernelRowScoreboard {
            row_id: "r1".into(),
            started_at: "t".into(),
            duration_secs: 1.5,
            command: "c".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![KernelTestResult {
                test_name: "t1".into(),
                status: KernelTestStatus::Pass,
                duration_secs: Some(0.5),
                reason: None,
            }],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 1,
                passed: 1,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        let j = serde_json::to_string(&sb).unwrap();
        let d: KernelRowScoreboard = serde_json::from_str(&j).unwrap();
        assert_eq!(d.summary.passed, 1);
    }

    #[test]
    fn matrix_summary_json_roundtrip() {
        let s = KernelMatrixSummary {
            started_at: "t".into(),
            duration_secs: 1.0,
            repo_commit: Some("abc".into()),
            repo_dirty: false,
            kernel_version: None,
            rows: vec![],
            gate: KernelGateReceipt {
                total_rows: 0,
                passed_rows: 0,
                product_fail_rows: 0,
                harness_fail_rows: 0,
                refused_rows: 0,
                skipped_rows: 0,
                gate_passed: false,
                verdict: "none".into(),
            },
        };
        let j = serde_json::to_string(&s).unwrap();
        let d: KernelMatrixSummary = serde_json::from_str(&j).unwrap();
        assert_eq!(d.gate.verdict, "none");
    }

    #[test]
    fn gate_verdicts() {
        let pass = KernelGateReceipt {
            total_rows: 5,
            passed_rows: 5,
            product_fail_rows: 0,
            harness_fail_rows: 0,
            refused_rows: 0,
            skipped_rows: 0,
            gate_passed: true,
            verdict: "gate passed".into(),
        };
        assert!(pass.gate_passed);

        let prod_fail = KernelGateReceipt {
            total_rows: 5,
            passed_rows: 3,
            product_fail_rows: 2,
            harness_fail_rows: 0,
            refused_rows: 0,
            skipped_rows: 0,
            gate_passed: false,
            verdict: "gate failed: 2 product failures, 0 harness failures, 0 rows refused".into(),
        };
        assert!(!prod_fail.gate_passed);

        let harness_fail = KernelGateReceipt {
            total_rows: 5,
            passed_rows: 3,
            product_fail_rows: 0,
            harness_fail_rows: 2,
            refused_rows: 0,
            skipped_rows: 0,
            gate_passed: false,
            verdict: "gate failed: 0 product failures, 2 harness failures, 0 rows refused".into(),
        };
        assert!(!harness_fail.gate_passed);
    }

    struct StubRunner;
    impl KernelMatrixRunner for StubRunner {
        fn run_row(&self, row: &KernelMatrixRow) -> KernelRowScoreboard {
            KernelRowScoreboard {
                row_id: row.row_id.clone(),
                started_at: "t".into(),
                duration_secs: 0.0,
                command: "stub".into(),
                kernel_version: None,
                results: vec![KernelTestResult {
                    test_name: "s".into(),
                    status: KernelTestStatus::EnvironmentRefusal,
                    duration_secs: None,
                    reason: Some("not available".into()),
                }],
                artifact_source: None,
                summary: KernelRowSummary {
                    total: 1,
                    passed: 0,
                    product_failures: 0,
                    harness_failures: 0,
                    skipped: 0,
                    refusals: 1,
                },
            }
        }
    }

    #[test]
    fn stub_runner_refuses_all() {
        let m = KernelValidationMatrix::default();
        let s = StubRunner.run_matrix(&m);
        assert_eq!(s.gate.total_rows, m.rows.len());
        assert!(!s.gate.gate_passed);
        assert!(s.gate.verdict.contains("refused"));
    }

    /// Guard test: proves `is_clean_pass` rejects rows without a real command
    /// and kernel version, preventing unbacked Pass claims for live-runtime tiers.
    #[test]
    fn guard_clean_pass_without_command_or_kernel_is_impossible() {
        // Empty command, zero failures/refusals => not clean pass
        let placeholder = KernelRowScoreboard {
            row_id: "ph".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "".into(),
            kernel_version: None,
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 1,
                passed: 1,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!placeholder.is_clean_pass());
        assert!(!placeholder.is_genuine_runtime_pass());

        // Clean pass without artifact => still not genuine runtime pass
        let clean_no_artifact = KernelRowScoreboard {
            row_id: "cna".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "run".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 2,
                passed: 2,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(clean_no_artifact.is_clean_pass());
        assert!(!clean_no_artifact.is_genuine_runtime_pass());

        // Genuine runtime pass requires artifact
        let genuine = KernelRowScoreboard {
            row_id: "g".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "run".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: Some(RuntimeArtifactSource {
                command: "run".into(),
                environment: "qemu".into(),
                commit: "abc".into(),
                kernel_version: Some("7.0.0".into()),
                exit_status: 0,
                stdout_path: None,
                stderr_path: None,
                workload_ran: true,
            }),
            summary: KernelRowSummary {
                total: 2,
                passed: 2,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(genuine.is_clean_pass());
        assert!(genuine.is_genuine_runtime_pass());
    }

    /// REL-VAL-006 guard: product failures are distinguished from harness failures.
    #[test]
    fn guard_product_vs_harness_failure_distinction() {
        let product = KernelRowScoreboard {
            row_id: "pf".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "run".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 5,
                passed: 3,
                product_failures: 2,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(product.has_product_failures());
        assert!(!product.has_harness_failures());
        assert!(!product.is_clean_pass());
        assert_eq!(product.summary.total_failures(), 2);

        let harness = KernelRowScoreboard {
            row_id: "hf".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "run".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: None,
            summary: KernelRowSummary {
                total: 5,
                passed: 3,
                product_failures: 0,
                harness_failures: 2,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!harness.has_product_failures());
        assert!(harness.has_harness_failures());
        assert!(!harness.is_clean_pass());
        assert_eq!(harness.summary.total_failures(), 2);
    }

    /// FRR-VAL-005: runtime-tier PASS must be impossible with an artifact
    /// whose workload_ran is false, regardless of other populated fields.
    #[test]
    fn guard_runtime_pass_impossible_with_workload_not_ran() {
        let non_ran_artifact = RuntimeArtifactSource {
            command: "./run-qemu.sh".into(),
            environment: "qemu".into(),
            commit: "abc".into(),
            kernel_version: Some("7.0.0".into()),
            exit_status: 0,
            stdout_path: Some("/log".into()),
            stderr_path: None,
            workload_ran: false,
        };
        let row = KernelRowScoreboard {
            row_id: "r1".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "./run-qemu.sh".into(),
            kernel_version: Some("7.0.0".into()),
            results: vec![],
            artifact_source: Some(non_ran_artifact),
            summary: KernelRowSummary {
                total: 1,
                passed: 1,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(row.is_clean_pass());
        assert!(!row.is_genuine_runtime_pass());
        assert!(
            row.artifact_source.is_some(),
            "artifact present but workload_ran=false"
        );
        assert!(
            !row.artifact_source.as_ref().unwrap().is_genuine(),
            "non-genuine artifact must not produce genuine pass"
        );
    }

    /// FRR-VAL-005: runtime-tier PASS must be impossible with an artifact
    /// whose command field is empty, even if workload_ran is true.
    #[test]
    fn guard_runtime_pass_impossible_with_empty_artifact_command() {
        let empty_cmd_artifact = RuntimeArtifactSource {
            command: "".into(),
            environment: "qemu".into(),
            commit: "abc".into(),
            kernel_version: Some("7.0.0".into()),
            exit_status: 0,
            stdout_path: Some("/log".into()),
            stderr_path: None,
            workload_ran: true,
        };
        let row = KernelRowScoreboard {
            row_id: "r2".into(),
            started_at: "t".into(),
            duration_secs: 0.0,
            command: "".into(),
            kernel_version: None,
            results: vec![],
            artifact_source: Some(empty_cmd_artifact),
            summary: KernelRowSummary {
                total: 1,
                passed: 1,
                product_failures: 0,
                harness_failures: 0,
                skipped: 0,
                refusals: 0,
            },
        };
        assert!(!row.is_clean_pass());
        assert!(!row.is_genuine_runtime_pass());
        assert!(
            row.artifact_source.is_some(),
            "artifact present but command field is empty"
        );
        assert!(
            !row.artifact_source.as_ref().unwrap().is_genuine(),
            "empty-command artifact must not produce genuine pass"
        );
        assert!(
            !RuntimeArtifactSource::is_genuine(row.artifact_source.as_ref().unwrap()),
            "is_genuine rejects empty command"
        );
    }
}
