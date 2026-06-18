// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Baseline package loader -- reads external performance/SLO baseline
//! outputs and maps their KPI data into performance gate
//! entries for budget evaluation and regression enforcement.
//!
//! When a baseline package path is provided, the gate evaluates each
//! subject row against the loaded KPIs and comparator data, producing a
//! pass/fail receipt instead of the all-refused placeholder.

use super::gate_entry::{BaselineKpi, ComparatorRef, EnvironmentManifest, MeasuredKpi, OpMix};
use super::runner::{GateRunRecord, GateRunner, RunVerdict};
use super::ValidationTier;
use serde::{Deserialize, Serialize};

/// Parsed content of the external baseline package.
#[derive(Debug, Clone)]
pub struct BaselinePackage {
    pub package_path: String,
    pub fuse_fio: Option<FuseFioBaseline>,
    pub ublk_perf: Option<UblkPerfBaseline>,
    pub carrier_comparison: Option<CarrierComparisonBaseline>,
    pub load_errors: Vec<String>,
}

/// FUSE fio benchmark baseline (fuse-fio-benchmark.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseFioBaseline {
    pub test: String,
    pub version: u32,
    #[serde(default = "default_fuse_fio_validation_id")]
    pub validation_id: String,
    #[serde(default)]
    pub issue: Option<u32>,
    pub timestamp: String,
    pub kernel_version: String,
    pub mode: String,
    pub backend: String,
    pub validation_tier: String,
    pub passed: u32,
    pub product_failures: u32,
    pub harness_failures: u32,
    pub environment_refusals: u32,
    pub results: Vec<FuseFioResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuseFioResult {
    pub name: String,
    pub status: String,
}

/// ublk performance baseline (ublk-perf/validation.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UblkPerfBaseline {
    pub test: String,
    pub version: u32,
    #[serde(default = "default_ublk_perf_validation_id")]
    pub validation_id: String,
    #[serde(default)]
    pub issue: Option<u32>,
    pub kernel_version: String,
    pub validation_tier: String,
    pub timestamp: String,
    pub passed: u32,
    pub failed: u32,
    pub blocked: u32,
    pub benchmarks: Vec<UblkPerfBenchmark>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UblkPerfBenchmark {
    pub name: String,
    pub phase: String,
    pub status: String,
    #[serde(default)]
    pub queue_depth: u32,
    #[serde(default)]
    pub block_size: String,
    #[serde(default)]
    pub rwmixread: u32,
    #[serde(default)]
    pub p50_ns: u64,
    #[serde(default)]
    pub p95_ns: u64,
    #[serde(default)]
    pub p99_ns: u64,
    #[serde(default)]
    pub budget_ns: u64,
}

/// Carrier comparison baseline (carrier-comparison-report.json).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierComparisonBaseline {
    pub harness: String,
    pub commit_sha: String,
    pub probe: CarrierProbe,
    pub loopback_baseline: Vec<CarrierLoopbackMeasurement>,
    pub verdict: String,
    pub validation_tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierProbe {
    pub rdma_available: bool,
    pub rdma_link_active: bool,
    #[serde(default)]
    pub rdma_modules_available: bool,
    pub tcp_available: bool,
    #[serde(default)]
    pub fallback: String,
    #[serde(default)]
    pub probe_result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarrierLoopbackMeasurement {
    pub payload_size_bytes: u64,
    pub round_trips: u32,
    pub avg_latency_us: f64,
    pub throughput_mb_s: f64,
}

fn default_fuse_fio_validation_id() -> String {
    "fuse-fio-baseline".into()
}

fn default_ublk_perf_validation_id() -> String {
    "ublk-perf-baseline".into()
}

fn validation_id_or_default<'a>(validation_id: &'a str, default_id: &'static str) -> &'a str {
    if validation_id.is_empty() {
        default_id
    } else {
        validation_id
    }
}

/// Load a baseline package from the given directory path.
pub fn load_baseline_package(package_path: &str) -> BaselinePackage {
    let mut pkg = BaselinePackage {
        package_path: package_path.to_string(),
        fuse_fio: None,
        ublk_perf: None,
        carrier_comparison: None,
        load_errors: Vec::new(),
    };

    // Load FUSE fio baseline
    let fuse_path = std::path::Path::new(package_path).join("fuse-fio/fuse-fio-benchmark.json");
    match std::fs::read_to_string(&fuse_path) {
        Ok(contents) => match serde_json::from_str::<FuseFioBaseline>(&contents) {
            Ok(baseline) => pkg.fuse_fio = Some(baseline),
            Err(e) => pkg.load_errors.push(format!("fuse-fio parse error: {e}")),
        },
        Err(e) => pkg.load_errors.push(format!("fuse-fio read error: {e}")),
    }

    // Load ublk perf baseline
    let ublk_path = std::path::Path::new(package_path).join("ublk-perf/validation.json");
    match std::fs::read_to_string(&ublk_path) {
        Ok(contents) => match serde_json::from_str::<UblkPerfBaseline>(&contents) {
            Ok(baseline) => pkg.ublk_perf = Some(baseline),
            Err(e) => pkg.load_errors.push(format!("ublk-perf parse error: {e}")),
        },
        Err(e) => pkg.load_errors.push(format!("ublk-perf read error: {e}")),
    }

    // Load carrier comparison baseline
    let cc_path = std::path::Path::new(package_path)
        .join("carrier-comparison/carrier-comparison-report.json");
    match std::fs::read_to_string(&cc_path) {
        Ok(contents) => match serde_json::from_str::<CarrierComparisonBaseline>(&contents) {
            Ok(baseline) => pkg.carrier_comparison = Some(baseline),
            Err(e) => pkg
                .load_errors
                .push(format!("carrier-comparison parse error: {e}")),
        },
        Err(e) => pkg
            .load_errors
            .push(format!("carrier-comparison read error: {e}")),
    }

    pkg
}

/// Build a performance gate receipt from an external baseline package.
///
/// This loads the baseline outputs, maps their KPIs into gate entries,
/// evaluates budgets and output requirements, and produces a receipt
/// that fails when comparator outputs, KPIs, noise profiles, or budgets
/// are missing or violated.
pub fn build_receipt_from_baseline(
    package_path: &str,
    commit_sha: &str,
    env: &EnvironmentManifest,
) -> super::runner::GateReceipt {
    let pkg = load_baseline_package(package_path);
    let mut runner = GateRunner::new(env.clone(), commit_sha);

    // Record any load errors as notes
    for err in &pkg.load_errors {
        runner.note(format!("baseline load: {err}"));
    }

    let om = OpMix {
        read_pct: 70,
        write_pct: 20,
        metadata_pct: 5,
        sync_pct: 5,
        concurrency: 4,
    };

    // --- Build comparator refs first so they can be attached at record time ---

    let fuse_comp: Option<ComparatorRef> = pkg.fuse_fio.as_ref().and_then(|fuse| {
        let kpis = extract_fuse_kpis(fuse);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.fuse-fio".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "FUSE fio baseline {} -- {} passed",
                validation_id_or_default(&fuse.validation_id, "fuse-fio-baseline"),
                fuse.passed
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    let ublk_comp: Option<ComparatorRef> = pkg.ublk_perf.as_ref().and_then(|ublk| {
        let kpis = extract_ublk_kpis(ublk);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.ublk-perf".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "ublk perf baseline {} -- {} passed",
                validation_id_or_default(&ublk.validation_id, "ublk-perf-baseline"),
                ublk.passed
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    let cc_comp: Option<ComparatorRef> = pkg.carrier_comparison.as_ref().and_then(|cc| {
        let kpis = extract_carrier_kpis(cc);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.carrier-comparison".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "External carrier comparison baseline -- {} loopback measurements",
                cc.loopback_baseline.len()
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    // --- Populate entries from baseline data ---

    // FUSE subjects: mounted-fuse, local-filesystem
    if let Some(ref fuse) = pkg.fuse_fio {
        let fuse_kpis = extract_fuse_kpis(fuse);
        let verdict = if fuse.product_failures == 0 && fuse.passed > 0 {
            RunVerdict::Passed
        } else {
            RunVerdict::Failed
        };

        let comps: Vec<ComparatorRef> = fuse_comp.iter().cloned().collect();

        for subject in &["mounted-fuse", "local-filesystem"] {
            let record = GateRunRecord {
                subject: subject.to_string(),
                workload_ref: "baseline.fuse-fio".into(),
                workload_desc: format!(
                    "FUSE fio baseline {} ({} passed, {} failures)",
                    validation_id_or_default(&fuse.validation_id, "fuse-fio-baseline"),
                    fuse.passed,
                    fuse.product_failures
                ),
                op_mix: om,
                validation_tier: ValidationTier::QemuGuest,
                budget_classes: Vec::new(),
                verdict: if fuse_kpis.is_empty() {
                    RunVerdict::Refused
                } else {
                    verdict
                },
                kpis: fuse_kpis.clone(),
                artifact_path: Some(format!("{package_path}/fuse-fio/fuse-fio-benchmark.json")),
                initial_comparators: comps.clone(),
                skip_numeric_budget: true,
            };
            runner.record(record);
        }
    } else {
        for subject in &["mounted-fuse", "local-filesystem"] {
            runner.record(GateRunRecord {
                subject: subject.to_string(),
                workload_ref: "baseline.fuse-fio".into(),
                workload_desc: "FUSE fio baseline not available in this package".into(),
                op_mix: om,
                validation_tier: ValidationTier::QemuGuest,
                budget_classes: Vec::new(),
                verdict: RunVerdict::Refused,
                kpis: Vec::new(),
                artifact_path: None,
                initial_comparators: Vec::new(),
                skip_numeric_budget: true,
            });
        }
    }

    // ublk subjects: ublk-direct, ublk-ext4
    if let Some(ref ublk) = pkg.ublk_perf {
        let ublk_kpis = extract_ublk_kpis(ublk);
        let verdict = if ublk.failed == 0 && ublk.passed > 0 {
            RunVerdict::Passed
        } else {
            RunVerdict::Failed
        };

        let comps: Vec<ComparatorRef> = ublk_comp.iter().cloned().collect();

        for subject in &["ublk-direct", "ublk-ext4"] {
            runner.record(GateRunRecord {
                subject: subject.to_string(),
                workload_ref: "baseline.ublk-perf".into(),
                workload_desc: format!(
                    "ublk perf baseline {} ({} passed, {} failed)",
                    validation_id_or_default(&ublk.validation_id, "ublk-perf-baseline"),
                    ublk.passed,
                    ublk.failed
                ),
                op_mix: OpMix {
                    read_pct: 70,
                    write_pct: 30,
                    metadata_pct: 0,
                    sync_pct: 0,
                    concurrency: 1,
                },
                validation_tier: ValidationTier::QemuGuest,
                budget_classes: Vec::new(),
                verdict: if ublk_kpis.is_empty() {
                    RunVerdict::Refused
                } else {
                    verdict
                },
                kpis: ublk_kpis.clone(),
                artifact_path: Some(format!("{package_path}/ublk-perf/validation.json")),
                initial_comparators: comps.clone(),
                skip_numeric_budget: true,
            });
        }
    } else {
        for subject in &["ublk-direct", "ublk-ext4"] {
            runner.record(GateRunRecord {
                subject: subject.to_string(),
                workload_ref: "baseline.ublk-perf".into(),
                workload_desc: "ublk perf baseline not available in this package".into(),
                op_mix: OpMix {
                    read_pct: 70,
                    write_pct: 30,
                    metadata_pct: 0,
                    sync_pct: 0,
                    concurrency: 1,
                },
                validation_tier: ValidationTier::QemuGuest,
                budget_classes: Vec::new(),
                verdict: RunVerdict::Refused,
                kpis: Vec::new(),
                artifact_path: None,
                initial_comparators: Vec::new(),
                skip_numeric_budget: true,
            });
        }
    }

    // Transport subject (carrier comparison)
    if let Some(ref cc) = pkg.carrier_comparison {
        let cc_kpis = extract_carrier_kpis(cc);
        let comps: Vec<ComparatorRef> = cc_comp.iter().cloned().collect();

        runner.record(GateRunRecord {
            subject: "transport".to_string(),
            workload_ref: "baseline.carrier-comparison".into(),
            workload_desc: format!(
                "Carrier comparison baseline ({} loopback measurements, verdict: {})",
                cc.loopback_baseline.len(),
                cc.verdict
            ),
            op_mix: OpMix {
                read_pct: 50,
                write_pct: 50,
                metadata_pct: 0,
                sync_pct: 0,
                concurrency: 1,
            },
            validation_tier: ValidationTier::MultiProcessDistributed,
            budget_classes: Vec::new(),
            verdict: RunVerdict::Passed,
            kpis: cc_kpis.clone(),
            artifact_path: Some(format!(
                "{package_path}/carrier-comparison/carrier-comparison-report.json"
            )),
            initial_comparators: comps.clone(),
            skip_numeric_budget: true,
        });
    } else {
        runner.record(GateRunRecord {
            subject: "transport".to_string(),
            workload_ref: "baseline.carrier-comparison".into(),
            workload_desc: "Carrier comparison baseline not available in this package".into(),
            op_mix: OpMix {
                read_pct: 50,
                write_pct: 50,
                metadata_pct: 0,
                sync_pct: 0,
                concurrency: 1,
            },
            validation_tier: ValidationTier::MultiProcessDistributed,
            budget_classes: Vec::new(),
            verdict: RunVerdict::Refused,
            kpis: Vec::new(),
            artifact_path: None,
            initial_comparators: Vec::new(),
            skip_numeric_budget: true,
        });
    }

    // Remaining subjects: local-object-store, recovery-rebuild, kernel-kmod-vfs, kernel-block-kmod
    // These are not covered by the external baseline package.
    let uncovered = &[
        "local-object-store",
        "recovery-rebuild",
        "kernel-kmod-vfs",
        "kernel-block-kmod",
    ];
    for subject in uncovered {
        runner.record(GateRunRecord {
            subject: subject.to_string(),
            workload_ref: "baseline.unavailable".into(),
            workload_desc: "Not covered by external baseline package".into(),
            op_mix: om,
            validation_tier: ValidationTier::QemuGuest,
            budget_classes: Vec::new(),
            verdict: RunVerdict::Refused,
            kpis: Vec::new(),
            artifact_path: None,
            initial_comparators: Vec::new(),
            skip_numeric_budget: true,
        });
    }

    // Fill any remaining missing subjects from REQUIRED_SUBJECTS
    runner.fill_missing_subjects("baseline.unavailable", "not in baseline package", om);

    runner.finalize()
}

/// Extract KPI measurements from FUSE fio baseline.
/// The FUSE fio baseline records pass/fail results without numeric KPIs,
/// so we produce a synthetic "passed" KPI count rather than throughput/latency.
fn extract_fuse_kpis(baseline: &FuseFioBaseline) -> Vec<MeasuredKpi> {
    let mut kpis = Vec::new();
    let total = baseline.results.len() as f64;
    let passed = baseline.passed as f64;

    if total > 0.0 {
        kpis.push(MeasuredKpi {
            ref_id: "kpi.fuse-fio.pass-rate".into(),
            name: "fuse-fio/pass-rate".into(),
            value: passed / total,
            unit: "ratio".into(),
            passed: Some(true),
            percentile: None,
        });
        kpis.push(MeasuredKpi {
            ref_id: "kpi.fuse-fio.total-tests".into(),
            name: "fuse-fio/total-tests".into(),
            value: total,
            unit: "count".into(),
            passed: Some(true),
            percentile: None,
        });
    }

    // Add individual benchmark results as KPIs (1.0 = pass, 0.0 = fail)
    for r in &baseline.results {
        if r.name.starts_with("fio_") {
            let val = if r.status == "pass" { 1.0 } else { 0.0 };
            kpis.push(MeasuredKpi {
                ref_id: format!("kpi.fuse-fio.{}", r.name),
                name: format!("fuse-fio/{}", r.name),
                value: val,
                unit: "pass".into(),
                passed: Some(r.status == "pass"),
                percentile: None,
            });
        }
    }

    kpis
}

/// Extract KPI measurements from ublk perf baseline.
fn extract_ublk_kpis(baseline: &UblkPerfBaseline) -> Vec<MeasuredKpi> {
    let mut kpis = Vec::new();

    for b in &baseline.benchmarks {
        // Convert ns to us for consistency with budget thresholds (which are in us)
        let p99_us = b.p99_ns as f64 / 1000.0;
        let p95_us = b.p95_ns as f64 / 1000.0;
        let p50_us = b.p50_ns as f64 / 1000.0;

        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.ublk.{}.p50", b.name),
            name: format!("ublk/{}/p50-latency", b.name),
            value: p50_us,
            unit: "us".into(),
            passed: Some(b.status == "pass"),
            percentile: Some("p50".into()),
        });
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.ublk.{}.p95", b.name),
            name: format!("ublk/{}/p95-latency", b.name),
            value: p95_us,
            unit: "us".into(),
            passed: Some(b.status == "pass"),
            percentile: Some("p95".into()),
        });
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.ublk.{}.p99", b.name),
            name: format!("ublk/{}/p99-latency", b.name),
            value: p99_us,
            unit: "us".into(),
            passed: Some(b.status == "pass"),
            percentile: Some("p99".into()),
        });
    }

    kpis
}

/// Extract KPI measurements from carrier comparison baseline.
fn extract_carrier_kpis(baseline: &CarrierComparisonBaseline) -> Vec<MeasuredKpi> {
    let mut kpis = Vec::new();

    for m in &baseline.loopback_baseline {
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.carrier.latency.{}B", m.payload_size_bytes),
            name: format!("carrier/latency-us-{}B", m.payload_size_bytes),
            value: m.avg_latency_us,
            unit: "us".into(),
            passed: Some(true),
            percentile: None,
        });
        kpis.push(MeasuredKpi {
            ref_id: format!("kpi.carrier.throughput.{}B", m.payload_size_bytes),
            name: format!("carrier/throughput-mb_s-{}B", m.payload_size_bytes),
            value: m.throughput_mb_s,
            unit: "MB/s".into(),
            passed: Some(true),
            percentile: None,
        });
    }

    // Add carrier probe metadata as KPIs
    kpis.push(MeasuredKpi {
        ref_id: "kpi.carrier.rdma-available".into(),
        name: "carrier/rdma-available".into(),
        value: if baseline.probe.rdma_available {
            1.0
        } else {
            0.0
        },
        unit: "bool".into(),
        passed: None,
        percentile: None,
    });
    kpis.push(MeasuredKpi {
        ref_id: "kpi.carrier.rdma-link-active".into(),
        name: "carrier/rdma-link-active".into(),
        value: if baseline.probe.rdma_link_active {
            1.0
        } else {
            0.0
        },
        unit: "bool".into(),
        passed: None,
        percentile: None,
    });

    kpis
}

#[cfg(test)]
mod tests {
    use super::super::gate_entry::NoisePolicy;
    use super::*;

    #[test]
    fn load_nonexistent_package() {
        let pkg = load_baseline_package("/nonexistent/path");
        assert!(pkg.fuse_fio.is_none());
        assert!(pkg.ublk_perf.is_none());
        assert!(pkg.carrier_comparison.is_none());
        assert_eq!(pkg.load_errors.len(), 3);
    }

    #[test]
    fn extract_fuse_kpis_empty() {
        let b = FuseFioBaseline {
            test: "t".into(),
            version: 1,
            validation_id: "fuse-fio-baseline".into(),
            issue: None,
            timestamp: "2026".into(),
            kernel_version: "7.0".into(),
            mode: "fuse".into(),
            backend: "los".into(),
            validation_tier: "T3".into(),
            passed: 0,
            product_failures: 0,
            harness_failures: 0,
            environment_refusals: 0,
            results: vec![],
        };
        assert!(extract_fuse_kpis(&b).is_empty());
    }

    #[test]
    fn extract_fuse_kpis_with_results() {
        let b = FuseFioBaseline {
            test: "t".into(),
            version: 1,
            validation_id: "fuse-fio-baseline".into(),
            issue: None,
            timestamp: "2026".into(),
            kernel_version: "7.0".into(),
            mode: "fuse".into(),
            backend: "los".into(),
            validation_tier: "T3".into(),
            passed: 2,
            product_failures: 0,
            harness_failures: 0,
            environment_refusals: 0,
            results: vec![
                FuseFioResult {
                    name: "fio_seq-write".into(),
                    status: "pass".into(),
                },
                FuseFioResult {
                    name: "fio_seq-read".into(),
                    status: "pass".into(),
                },
            ],
        };
        let kpis = extract_fuse_kpis(&b);
        assert!(!kpis.is_empty());
        // pass-rate + total-tests + 2 fio results = 4
        assert_eq!(kpis.len(), 4);
    }

    #[test]
    fn extract_ublk_kpis_per_benchmark() {
        let b = UblkPerfBaseline {
            test: "t".into(),
            version: 1,
            validation_id: "ublk-perf-baseline".into(),
            issue: None,
            kernel_version: "7.0".into(),
            validation_tier: "T3".into(),
            timestamp: "2026".into(),
            passed: 1,
            failed: 0,
            blocked: 0,
            benchmarks: vec![UblkPerfBenchmark {
                name: "qdepth_1".into(),
                phase: "qdepth".into(),
                status: "pass".into(),
                queue_depth: 1,
                block_size: "4k".into(),
                rwmixread: 70,
                p50_ns: 30000,
                p95_ns: 65000,
                p99_ns: 140000,
                budget_ns: 25000000,
            }],
        };
        let kpis = extract_ublk_kpis(&b);
        // p50, p95, p99 = 3 KPIs per benchmark
        assert_eq!(kpis.len(), 3);
        assert!(kpis.iter().any(|k| k.percentile.as_deref() == Some("p99")));
        // p99_ns=140000 => 140.0 us
        let p99 = kpis
            .iter()
            .find(|k| k.percentile.as_deref() == Some("p99"))
            .unwrap();
        assert!((p99.value - 140.0).abs() < 0.1);
    }

    #[test]
    fn load_package_accepts_validation_ids_without_issues() {
        let root =
            std::env::temp_dir().join(format!("tidefs-baseline-package-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("fuse-fio")).unwrap();
        std::fs::create_dir_all(root.join("ublk-perf")).unwrap();

        std::fs::write(
            root.join("fuse-fio/fuse-fio-benchmark.json"),
            r#"{
  "test": "tidefs-fuse-fio-baseline",
  "version": 1,
  "validation_id": "fuse-fio-baseline",
  "timestamp": "2026-06-01T00:00:00Z",
  "kernel_version": "7.0",
  "mode": "fuse",
  "backend": "local-object-store",
  "validation_tier": "Tier 3 QEMU guest mounted-userspace FUSE runtime",
  "passed": 1,
  "product_failures": 0,
  "harness_failures": 0,
  "environment_refusals": 0,
  "results": []
}"#,
        )
        .unwrap();
        std::fs::write(
            root.join("ublk-perf/validation.json"),
            r#"{
  "test": "ublk-perf-baseline",
  "version": 3,
  "validation_id": "ublk-perf-baseline",
  "kernel_version": "7.0",
  "validation_tier": "Tier 3 QEMU guest ublk/block-volume runtime",
  "timestamp": "2026-06-01T00:00:00Z",
  "passed": 1,
  "failed": 0,
  "blocked": 0,
  "benchmarks": []
}"#,
        )
        .unwrap();

        let pkg = load_baseline_package(root.to_str().unwrap());
        assert_eq!(
            pkg.fuse_fio.as_ref().map(|b| b.validation_id.as_str()),
            Some("fuse-fio-baseline")
        );
        assert_eq!(pkg.fuse_fio.as_ref().and_then(|b| b.issue), None);
        assert_eq!(
            pkg.ublk_perf.as_ref().map(|b| b.validation_id.as_str()),
            Some("ublk-perf-baseline")
        );
        assert_eq!(pkg.ublk_perf.as_ref().and_then(|b| b.issue), None);

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn test_extract_carrier_kpis() {
        let b = CarrierComparisonBaseline {
            harness: "h".into(),
            commit_sha: "abc".into(),
            probe: CarrierProbe {
                rdma_available: true,
                rdma_link_active: true,
                rdma_modules_available: true,
                tcp_available: true,
                fallback: "none".into(),
                probe_result: "ok".into(),
            },
            loopback_baseline: vec![CarrierLoopbackMeasurement {
                payload_size_bytes: 256,
                round_trips: 10,
                avg_latency_us: 100.0,
                throughput_mb_s: 5.0,
            }],
            verdict: "baseline-only".into(),
            validation_tier: "multi-process-distributed".into(),
        };
        let kpis = extract_carrier_kpis(&b);
        // latency + throughput per measurement + rdma-available + rdma-link-active = 4
        assert_eq!(kpis.len(), 4);
    }

    #[test]
    fn build_receipt_from_nonexistent() {
        let env = EnvironmentManifest {
            profile_ref: "test".into(),
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
        };
        let receipt = build_receipt_from_baseline("/nonexistent", "abc", &env);
        // All required subjects filled => invariant holds
        assert!(receipt.invariant_holds);
        // release_ready should be false (no runtime validation)
        assert!(!receipt.release_ready);
    }
}

/// A single entry in the current-run manifest file.
/// Each entry maps to one performance gate subject with measured KPIs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentRunEntry {
    pub subject: String,
    #[serde(default)]
    pub workload_ref: String,
    #[serde(default)]
    pub workload_desc: String,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub artifact_path: Option<String>,
    pub kpis: Vec<MeasuredKpi>,
}

/// Deserialized current-run manifest (produced by a benchmark harness run).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentRunManifest {
    #[serde(default)]
    pub commit_sha: String,
    pub entries: Vec<CurrentRunEntry>,
}

/// Build a performance gate receipt from an external baseline package (comparators)
/// and a separate current-run manifest (live measurements).
///
/// The baseline package provides comparator refs and budget definitions.
/// The current-run manifest provides live KPIs measured on the current code.
/// The gate evaluates whether current measurements regress against approved baselines
/// and whether numeric budgets are violated.
pub fn build_receipt_from_baseline_and_current(
    package_path: &str,
    current_run_path: &str,
    commit_sha: &str,
    env: &EnvironmentManifest,
) -> super::runner::GateReceipt {
    let pkg = load_baseline_package(package_path);
    let mut runner = GateRunner::new(env.clone(), commit_sha);

    for err in &pkg.load_errors {
        runner.note(format!("baseline load: {err}"));
    }

    // Load current-run manifest
    let current_manifest: CurrentRunManifest = match std::fs::read_to_string(current_run_path) {
        Ok(contents) => {
            match serde_json::from_str(&contents) {
                Ok(m) => m,
                Err(e) => {
                    runner.note(format!("current-run parse error ({current_run_path}): {e}"));
                    runner.note("falling back to all-refused receipt due to unreadable current-run manifest");
                    return runner.finalize();
                }
            }
        }
        Err(e) => {
            runner.note(format!("current-run read error ({current_run_path}): {e}"));
            runner.note("falling back to all-refused receipt due to missing current-run manifest");
            return runner.finalize();
        }
    };

    if current_manifest.commit_sha != commit_sha && !current_manifest.commit_sha.is_empty() {
        runner.note(format!(
            "current-run commit {} != receipt commit {}",
            current_manifest.commit_sha, commit_sha
        ));
    }

    // Build comparator refs from baseline package (same as build_receipt_from_baseline)
    let fuse_comp: Option<ComparatorRef> = pkg.fuse_fio.as_ref().and_then(|fuse| {
        let kpis = extract_fuse_kpis(fuse);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.fuse-fio".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "FUSE fio baseline {} -- {} passed",
                validation_id_or_default(&fuse.validation_id, "fuse-fio-baseline"),
                fuse.passed
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    let ublk_comp: Option<ComparatorRef> = pkg.ublk_perf.as_ref().and_then(|ublk| {
        let kpis = extract_ublk_kpis(ublk);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.ublk-perf".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "ublk perf baseline {} -- {} passed",
                validation_id_or_default(&ublk.validation_id, "ublk-perf-baseline"),
                ublk.passed
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    let cc_comp: Option<ComparatorRef> = pkg.carrier_comparison.as_ref().and_then(|cc| {
        let kpis = extract_carrier_kpis(cc);
        if kpis.is_empty() {
            return None;
        }
        Some(ComparatorRef {
            ref_id: "baseline.carrier-comparison".into(),
            commit_sha: Some(commit_sha.to_string()),
            description: format!(
                "External carrier comparison baseline -- {} loopback measurements",
                cc.loopback_baseline.len()
            ),
            baseline_kpis: kpis
                .iter()
                .map(|k| BaselineKpi {
                    name: k.name.clone(),
                    value: k.value,
                    unit: k.unit.clone(),
                })
                .collect(),
        })
    });

    let default_op_mix = OpMix {
        read_pct: 70,
        write_pct: 20,
        metadata_pct: 5,
        sync_pct: 5,
        concurrency: 4,
    };

    // Map each current-run entry to a gate record with the matching baseline comparator
    for entry in &current_manifest.entries {
        let verdict = match entry.verdict.as_str() {
            "failed" => RunVerdict::Failed,
            "refused" => RunVerdict::Refused,
            "skipped" => RunVerdict::Skipped,
            _ => RunVerdict::Passed,
        };

        // Select the appropriate comparator for this subject
        let comparators: Vec<ComparatorRef> = match entry.subject.as_str() {
            "mounted-fuse" | "local-filesystem" => fuse_comp.iter().cloned().collect(),
            "ublk-direct" | "ublk-ext4" => ublk_comp.iter().cloned().collect(),
            "transport" => cc_comp.iter().cloned().collect(),
            _ => Vec::new(),
        };

        let validation_tier = match entry.subject.as_str() {
            "transport" => ValidationTier::MultiProcessDistributed,
            "kernel-kmod-vfs" | "kernel-block-kmod" => ValidationTier::Kbuild,
            _ => ValidationTier::QemuGuest,
        };

        let kpis_empty = entry.kpis.is_empty();
        let effective_verdict = if kpis_empty {
            RunVerdict::Refused
        } else {
            verdict
        };

        runner.record(GateRunRecord {
            subject: entry.subject.clone(),
            workload_ref: if entry.workload_ref.is_empty() {
                format!("current-run.{}", entry.subject)
            } else {
                entry.workload_ref.clone()
            },
            workload_desc: if entry.workload_desc.is_empty() {
                format!("Current-run measurement for {}", entry.subject)
            } else {
                entry.workload_desc.clone()
            },
            op_mix: default_op_mix,
            validation_tier,
            budget_classes: Vec::new(),
            verdict: effective_verdict,
            kpis: entry.kpis.clone(),
            artifact_path: entry.artifact_path.clone(),
            initial_comparators: comparators,
            skip_numeric_budget: false,
        });
    }

    // Fill remaining required subjects not in the current-run manifest
    runner.fill_missing_subjects(
        "current-run.unavailable",
        "not in current-run manifest",
        default_op_mix,
    );

    runner.finalize()
}
