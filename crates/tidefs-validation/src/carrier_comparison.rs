// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! RDMA versus TCP carrier performance comparison (NEXT-PERF-007).
//!
//! Runs the same workload (deterministic loopback round-trip via
//! tidefs-two-node-harness) and classifies the available transport carrier
//! via rdma-probe.  Produces a structured CarrierComparisonReport with
//! carrier mode, throughput, latency, and fallback disclosures.
//!
//! When neither TCP nor RDMA runtime is reachable (e.g. no /dev/kvm, no
//! SoftRoCE, no active RDMA link), the loopback baseline is recorded and
//! the comparison is blocked on environment refusal.

use serde::{Deserialize, Serialize};
use std::process::Command;

// ── Carrier comparison types ──────────────────────────────────────────

/// Mode of the transport carrier under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CarrierMode {
    LoopbackDeterministic,
    Tcp,
    Rdma,
    Unknown,
}

impl CarrierMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::LoopbackDeterministic => "loopback-deterministic",
            Self::Tcp => "tcp",
            Self::Rdma => "rdma",
            Self::Unknown => "unknown",
        }
    }
}

/// A single measurement point for one payload size.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierMeasurement {
    pub payload_size_bytes: usize,
    pub round_trips: u32,
    pub avg_latency_us: f64,
    pub total_bytes_per_rt: u64,
    pub throughput_mb_s: f64,
}

/// Carrier capability classification from rdma-probe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierProbe {
    pub rdma_available: bool,
    pub rdma_link_active: bool,
    pub rdma_modules_available: bool,
    pub tcp_available: bool,
    pub fallback: String,
    pub probe_result: String,
}

/// The full carrier comparison report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierComparisonReport {
    pub harness: String,
    pub commit_sha: String,
    pub probe: CarrierProbe,
    pub loopback_baseline: Vec<CarrierMeasurement>,
    pub tcp_comparison: Option<CarrierComparisonResult>,
    pub rdma_comparison: Option<CarrierComparisonResult>,
    pub verdict: CarrierComparisonVerdict,
    pub validation_tier: String,
    pub artifact_path: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CarrierComparisonResult {
    pub carrier: CarrierMode,
    pub reachable: bool,
    pub measurements: Vec<CarrierMeasurement>,
    pub blocker: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CarrierComparisonVerdict {
    BaselineOnly,
    PartialTcp,
    PartialRdma,
    FullComparison,
    EnvironmentRefusal,
}

// ── Probe runner ──────────────────────────────────────────────────────

/// Run `nix/tidefs-rdma-probe.sh` and parse its key=value output into a
/// CarrierProbe.
pub fn run_rdma_probe(workspace_root: &str) -> CarrierProbe {
    let probe_script = format!("{workspace_root}/nix/tidefs-rdma-probe.sh");
    let output = Command::new("bash")
        .arg(&probe_script)
        .output()
        .unwrap_or_else(|e| std::process::Output {
            status: std::process::ExitStatus::default(),
            stdout: Vec::new(),
            stderr: e.to_string().into_bytes(),
        });

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let probe_result = extract_kv(&stdout, "rdma_carrier_probe_result").unwrap_or_else(|| {
        if stderr.contains("rdma-probe") || !stderr.is_empty() {
            "probe_failed".to_string()
        } else {
            "unknown".to_string()
        }
    });

    let rdma_status = extract_kv(&stdout, "transport_session_0_rdma_status")
        .unwrap_or_else(|| "unknown".to_string());
    let fallback = extract_kv(&stdout, "transport_session_0_fallback")
        .unwrap_or_else(|| "unknown".to_string());
    let rdma_modules = extract_kv(&stdout, "module_rdma_rxe_available")
        .map(|v| v == "yes")
        .unwrap_or(false);
    let rdma_link_active = probe_result.contains("active")
        || extract_kv(&stdout, "rdma_links_visible")
            .map(|v| v.parse::<u32>().unwrap_or(0) > 0)
            .unwrap_or(false);

    CarrierProbe {
        rdma_available: rdma_modules || rdma_link_active,
        rdma_link_active,
        rdma_modules_available: rdma_modules,
        tcp_available: !fallback.contains("tcp_required") || fallback.contains("available"),
        fallback: format!("{rdma_status} => {fallback}"),
        probe_result,
    }
}

#[cfg(test)]
/// Resolve the workspace root by walking up from the crate manifest directory
/// until we find `.git` or `nix/tidefs-rdma-probe.sh`.
fn resolve_workspace_root() -> String {
    let mut dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        if dir.join(".git").exists() || dir.join("nix/tidefs-rdma-probe.sh").exists() {
            return dir.to_string_lossy().to_string();
        }
        match dir.parent() {
            Some(parent) => dir = parent.to_path_buf(),
            None => break,
        }
    }
    // Fallback to CARGO_MANIFEST_DIR
    env!("CARGO_MANIFEST_DIR").to_string()
}

fn extract_kv(stdout: &str, key: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some((k, v)) = line.trim().split_once('=') {
            if k.trim() == key {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

// ── Two-node harness integration ──────────────────────────────────────

/// Run the two-node harness transport budget measurement and return the
/// parsed measurements.  Uses the deterministic loopback carrier.
pub fn run_loopback_baseline(
    repo_root: &str,
    target_dir: &str,
) -> (Vec<CarrierMeasurement>, Option<String>) {
    let output = Command::new("cargo")
        .args([
            "test",
            "-p",
            "tidefs-two-node-harness",
            "--test",
            "transport_budget",
            "transport_budget_measure",
            "--",
            "--nocapture",
            "--ignored",
        ])
        .env("CARGO_TARGET_DIR", target_dir)
        .env("CARGO_BUILD_JOBS", "1")
        .env("RUST_TEST_THREADS", "1")
        .current_dir(repo_root)
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);

            if !o.status.success() {
                let exit = o.status.code().unwrap_or(-1);
                let reason = format!(
                    "two-node harness transport_budget_measure failed (exit {exit}): {}",
                    tail_str(&stderr, 200)
                );
                return (Vec::new(), Some(reason));
            }

            let measurements = parse_transport_budget_measurements(&stdout);
            if measurements.is_empty() {
                return (
                    Vec::new(),
                    Some("transport budget produced no measurements".to_string()),
                );
            }
            (measurements, None)
        }
        Err(e) => (Vec::new(), Some(format!("spawn failed: {e}"))),
    }
}

fn parse_transport_budget_measurements(stdout: &str) -> Vec<CarrierMeasurement> {
    let begin = match stdout.find("TRANSPORT_BUDGET_JSON_BEGIN") {
        Some(p) => p + "TRANSPORT_BUDGET_JSON_BEGIN".len(),
        None => return Vec::new(),
    };
    let end = match stdout[begin..].find("TRANSPORT_BUDGET_JSON_END") {
        Some(p) => begin + p,
        None => return Vec::new(),
    };
    let json_block = stdout[begin..end].trim();

    let val: serde_json::Value = match serde_json::from_str(json_block) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let mut measurements = Vec::new();
    if let Some(arr) = val.get("measurements").and_then(|m| m.as_array()) {
        for m in arr {
            let size = m
                .get("payload_size_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let rt = m.get("round_trips").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let lat = m
                .get("avg_latency_us")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let bytes = m
                .get("total_bytes_per_rt")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let tp = m
                .get("throughput_mb_s")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            measurements.push(CarrierMeasurement {
                payload_size_bytes: size,
                round_trips: rt,
                avg_latency_us: lat,
                total_bytes_per_rt: bytes,
                throughput_mb_s: tp,
            });
        }
    }
    measurements
}

// ── Comparison logic ──────────────────────────────────────────────────

/// Produce a full carrier comparison report.
pub fn compare_carriers(
    repo_root: &str,
    target_dir: &str,
    commit_sha: &str,
    artifact_dir: Option<&str>,
) -> CarrierComparisonReport {
    let probe = run_rdma_probe(repo_root);

    let (loopback_baseline, baseline_blocker) = run_loopback_baseline(repo_root, target_dir);

    let mut notes: Vec<String> = Vec::new();

    // TCP comparison
    let tcp = if probe.tcp_available {
        notes.push("TCP carrier not reachable: requires live multi-process transport session over TCP stack".to_string());
        CarrierComparisonResult {
            carrier: CarrierMode::Tcp,
            reachable: false,
            measurements: Vec::new(),
            blocker: Some(
                "TCP runtime requires QEMU guest or host multi-process environment with loopback TCP".to_string(),
            ),
        }
    } else {
        notes.push(
            "TCP fallback required per rdma-probe; TCP not independently measured".to_string(),
        );
        CarrierComparisonResult {
            carrier: CarrierMode::Tcp,
            reachable: false,
            measurements: Vec::new(),
            blocker: Some(
                "TCP carrier measurement pending — rdma-probe reports tcp_required fallback"
                    .to_string(),
            ),
        }
    };

    // RDMA comparison
    let rdma = if probe.rdma_link_active {
        notes.push(
            "RDMA link active but two-node harness does not yet exercise RDMA data path"
                .to_string(),
        );
        CarrierComparisonResult {
            carrier: CarrierMode::Rdma,
            reachable: false,
            measurements: Vec::new(),
            blocker: Some(
                "RDMA data-path measurement pending: two-node harness only exercises loopback"
                    .to_string(),
            ),
        }
    } else if probe.rdma_modules_available {
        notes.push(
            "RDMA modules available but no active link; SoftRoCE can be enabled in QEMU guest"
                .to_string(),
        );
        CarrierComparisonResult {
            carrier: CarrierMode::Rdma,
            reachable: false,
            measurements: Vec::new(),
            blocker: Some(
                "RDMA requires active link: enable SoftRoCE (rxe) on QEMU guest with /dev/kvm"
                    .to_string(),
            ),
        }
    } else {
        notes.push("RDMA not available: no hardware, no software modules".to_string());
        CarrierComparisonResult {
            carrier: CarrierMode::Rdma,
            reachable: false,
            measurements: Vec::new(),
            blocker: Some("RDMA hardware/software not available in this environment".to_string()),
        }
    };

    // Determine verdict
    let verdict = if loopback_baseline.is_empty() {
        if let Some(ref b) = baseline_blocker {
            notes.push(format!("loopback baseline blocked: {b}"));
        }
        CarrierComparisonVerdict::EnvironmentRefusal
    } else if !tcp.measurements.is_empty() && !rdma.measurements.is_empty() {
        CarrierComparisonVerdict::FullComparison
    } else if !rdma.measurements.is_empty() {
        CarrierComparisonVerdict::PartialRdma
    } else if !tcp.measurements.is_empty() {
        CarrierComparisonVerdict::PartialTcp
    } else {
        CarrierComparisonVerdict::BaselineOnly
    };

    // Compute artifact path
    let artifact_path = artifact_dir.map(|d| format!("{d}/carrier-comparison-report.json"));

    CarrierComparisonReport {
        harness: "tidefs-two-node-harness".to_string(),
        commit_sha: commit_sha.to_string(),
        probe,
        loopback_baseline,
        tcp_comparison: Some(tcp),
        rdma_comparison: Some(rdma),
        verdict,
        validation_tier: "multi-process-distributed".to_string(),
        artifact_path,
        notes,
    }
}

/// Render the carrier comparison report as markdown.
pub fn render_markdown(report: &CarrierComparisonReport) -> String {
    let mut md = String::new();
    md.push_str("# RDMA vs TCP Carrier Performance Comparison\n\n");
    md.push_str(&format!("**Commit**: `{}`\n", report.commit_sha));
    md.push_str(&format!(
        "**Validation Tier**: {}\n",
        report.validation_tier
    ));
    md.push_str(&format!("**Verdict**: {:?}\n\n", report.verdict));

    // Probe section
    md.push_str("## Carrier Probe\n\n");
    md.push_str("| Attribute | Value |\n");
    md.push_str("|-----------|-------|\n");
    md.push_str(&format!(
        "| RDMA available | {} |\n",
        report.probe.rdma_available
    ));
    md.push_str(&format!(
        "| RDMA link active | {} |\n",
        report.probe.rdma_link_active
    ));
    md.push_str(&format!(
        "| RDMA modules available | {} |\n",
        report.probe.rdma_modules_available
    ));
    md.push_str(&format!(
        "| TCP available | {} |\n",
        report.probe.tcp_available
    ));
    md.push_str(&format!("| Fallback | {} |\n", report.probe.fallback));
    md.push_str(&format!(
        "| Probe result | {} |\n\n",
        report.probe.probe_result
    ));

    // Loopback baseline
    md.push_str("## Loopback Baseline\n\n");
    if report.loopback_baseline.is_empty() {
        md.push_str("(no measurements)\n\n");
    } else {
        md.push_str("| Payload (B) | Round-trips | Avg Latency (us) | Throughput (MB/s) |\n");
        md.push_str("|------------|------------|-----------------|------------------|\n");
        for m in &report.loopback_baseline {
            md.push_str(&format!(
                "| {} | {} | {:.1} | {:.2} |\n",
                m.payload_size_bytes, m.round_trips, m.avg_latency_us, m.throughput_mb_s,
            ));
        }
        md.push('\n');
    }

    // TCP comparison
    md.push_str("## TCP Comparison\n\n");
    if let Some(ref tcp) = report.tcp_comparison {
        md.push_str(&format!("**Reachable**: {}\n", tcp.reachable));
        if let Some(ref b) = tcp.blocker {
            md.push_str(&format!("**Blocker**: {b}\n"));
        }
        if !tcp.measurements.is_empty() {
            md.push_str("\n| Payload (B) | Avg Latency (us) | Throughput (MB/s) |\n");
            md.push_str("|------------|-----------------|------------------|\n");
            for m in &tcp.measurements {
                md.push_str(&format!(
                    "| {} | {:.1} | {:.2} |\n",
                    m.payload_size_bytes, m.avg_latency_us, m.throughput_mb_s,
                ));
            }
        }
        md.push('\n');
    }

    // RDMA comparison
    md.push_str("## RDMA Comparison\n\n");
    if let Some(ref rdma) = report.rdma_comparison {
        md.push_str(&format!("**Reachable**: {}\n", rdma.reachable));
        if let Some(ref b) = rdma.blocker {
            md.push_str(&format!("**Blocker**: {b}\n"));
        }
        if !rdma.measurements.is_empty() {
            md.push_str("\n| Payload (B) | Avg Latency (us) | Throughput (MB/s) |\n");
            md.push_str("|------------|-----------------|------------------|\n");
            for m in &rdma.measurements {
                md.push_str(&format!(
                    "| {} | {:.1} | {:.2} |\n",
                    m.payload_size_bytes, m.avg_latency_us, m.throughput_mb_s,
                ));
            }
        }
        md.push('\n');
    }

    // Notes
    if !report.notes.is_empty() {
        md.push_str("## Notes\n\n");
        for n in &report.notes {
            md.push_str(&format!("- {n}\n"));
        }
        md.push('\n');
    }

    // Artifact
    if let Some(ref ap) = report.artifact_path {
        md.push_str(&format!("**Artifact path**: `{ap}`\n"));
    }

    md
}

fn tail_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("...{}", &s[s.len() - max..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn carrier_mode_labels() {
        assert_eq!(
            CarrierMode::LoopbackDeterministic.label(),
            "loopback-deterministic"
        );
        assert_eq!(CarrierMode::Tcp.label(), "tcp");
        assert_eq!(CarrierMode::Rdma.label(), "rdma");
        assert_eq!(CarrierMode::Unknown.label(), "unknown");
    }

    #[test]
    fn probe_from_empty_stdout() {
        let probe = run_rdma_probe("/nonexistent/repo");
        assert_eq!(probe.probe_result, "probe_failed");
        assert!(!probe.rdma_available);
    }

    #[test]
    fn probe_with_real_repo() {
        let probe = run_rdma_probe(&resolve_workspace_root());
        assert!(!probe.probe_result.is_empty());
        assert!(!probe.fallback.is_empty());
    }

    #[test]
    fn parse_empty_measurements() {
        let m = parse_transport_budget_measurements("");
        assert!(m.is_empty());
    }

    #[test]
    fn parse_valid_measurements() {
        let json = serde_json::json!({
            "harness": "tidefs-two-node-harness",
            "carrier": "loopback-deterministic",
            "carrier_disclosure": {
                "mode": "loopback",
                "tcp_available": false,
                "rdma_available": false
            },
            "measurements": [
                {"payload_size_bytes": 256, "round_trips": 10,
                 "avg_latency_us": 42.0, "total_bytes_per_rt": 512,
                 "throughput_mb_s": 11.6}
            ],
            "kpi_version": 1
        });
        let stdout = format!(
            "TRANSPORT_BUDGET_JSON_BEGIN\n{}\nTRANSPORT_BUDGET_JSON_END",
            serde_json::to_string_pretty(&json).unwrap()
        );
        let m = parse_transport_budget_measurements(&stdout);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].payload_size_bytes, 256);
        assert_eq!(m[0].avg_latency_us, 42.0);
        assert!((m[0].throughput_mb_s - 11.6).abs() < 0.01);
    }

    #[test]
    fn report_serialization_roundtrip() {
        let report = CarrierComparisonReport {
            harness: "test".to_string(),
            commit_sha: "abc".to_string(),
            probe: CarrierProbe {
                rdma_available: false,
                rdma_link_active: false,
                rdma_modules_available: true,
                tcp_available: false,
                fallback: "blocked => tcp_required".to_string(),
                probe_result: "blocked_no_active_link".to_string(),
            },
            loopback_baseline: vec![CarrierMeasurement {
                payload_size_bytes: 256,
                round_trips: 10,
                avg_latency_us: 42.0,
                total_bytes_per_rt: 512,
                throughput_mb_s: 11.6,
            }],
            tcp_comparison: Some(CarrierComparisonResult {
                carrier: CarrierMode::Tcp,
                reachable: false,
                measurements: vec![],
                blocker: Some("blocked".to_string()),
            }),
            rdma_comparison: Some(CarrierComparisonResult {
                carrier: CarrierMode::Rdma,
                reachable: false,
                measurements: vec![],
                blocker: Some("blocked".to_string()),
            }),
            verdict: CarrierComparisonVerdict::BaselineOnly,
            validation_tier: "multi-process-distributed".to_string(),
            artifact_path: Some("/tmp/test.json".to_string()),
            notes: vec!["test note".to_string()],
        };
        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: CarrierComparisonReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.commit_sha, "abc");
        assert_eq!(back.verdict, CarrierComparisonVerdict::BaselineOnly);
        assert!(back.tcp_comparison.is_some());
    }

    #[test]
    fn markdown_renders() {
        let report = CarrierComparisonReport {
            harness: "test".to_string(),
            commit_sha: "abc".to_string(),
            probe: CarrierProbe {
                rdma_available: false,
                rdma_link_active: false,
                rdma_modules_available: false,
                tcp_available: false,
                fallback: "none => none".to_string(),
                probe_result: "none".to_string(),
            },
            loopback_baseline: vec![],
            tcp_comparison: None,
            rdma_comparison: None,
            verdict: CarrierComparisonVerdict::EnvironmentRefusal,
            validation_tier: "multi-process-distributed".to_string(),
            artifact_path: None,
            notes: vec![],
        };
        let md = render_markdown(&report);
        assert!(md.contains("EnvironmentRefusal"));
        assert!(md.contains("Carrier Probe"));
    }

    #[test]
    fn extract_kv_parses() {
        let stdout = "key1=value1\n  key2 = value2\nkey3=value3\n";
        assert_eq!(extract_kv(stdout, "key1"), Some("value1".to_string()));
        assert_eq!(extract_kv(stdout, "key2"), Some("value2".to_string()));
        assert_eq!(extract_kv(stdout, "key3"), Some("value3".to_string()));
        assert_eq!(extract_kv(stdout, "key4"), None);
    }

    #[test]
    fn compare_carriers_in_this_env() {
        let report = compare_carriers(
            &resolve_workspace_root(),
            &std::env::var("CARGO_TARGET_DIR")
                .unwrap_or_else(|_| "/tmp/tidefs-workers/s3/cargo-target".to_string()),
            "test-sha",
            None,
        );
        assert!(!report.probe.probe_result.is_empty());
        assert!(matches!(
            report.verdict,
            CarrierComparisonVerdict::BaselineOnly | CarrierComparisonVerdict::EnvironmentRefusal
        ));
    }
    #[test]
    fn write_validation_report() {
        if std::env::var("TIDEFS_WRITE_VALIDATION").as_deref() != Ok("1") {
            eprintln!("SKIP: set TIDEFS_WRITE_VALIDATION=1 to write validation");
            return;
        }
        let repo_root = resolve_workspace_root();
        let target_dir = std::env::var("CARGO_TARGET_DIR")
            .unwrap_or_else(|_| "/tmp/tidefs-workers/s3/cargo-target".to_string());
        let commit_sha =
            std::env::var("TIDEFS_VALIDATION_COMMIT_SHA").unwrap_or_else(|_| "unknown".to_string());
        let validation_dir = std::env::var("TIDEFS_CARRIER_COMPARISON_VALIDATION_DIR")
            .unwrap_or_else(|_| {
                format!("{repo_root}//root/ai/tmp/tidefs-validation/6502-carrier-comparison")
            });
        std::fs::create_dir_all(&validation_dir).expect("create validation dir");
        let report = compare_carriers(&repo_root, &target_dir, &commit_sha, Some(&validation_dir));
        let json_path = format!("{validation_dir}/carrier-comparison-report.json");
        let json_str = serde_json::to_string_pretty(&report).expect("serialize");
        std::fs::write(&json_path, &json_str).expect("write json");
        let md_path = format!("{validation_dir}/carrier-comparison-report.md");
        let md_str = render_markdown(&report);
        std::fs::write(&md_path, &md_str).expect("write md");
        let probe_path = format!("{validation_dir}/rdma-probe-output.txt");
        let probe_output = std::process::Command::new("bash")
            .arg(format!("{repo_root}/nix/tidefs-rdma-probe.sh"))
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|e| format!("probe failed: {e}"));
        std::fs::write(&probe_path, &probe_output).expect("write probe");
        let env_path = format!("{validation_dir}/environment.txt");
        let env_facts = format!(
            "commit: {commit_sha}
             hostname: {}
             kernel: {}
             kvm: {}
             fuse: {}
             validation_tier: multi-process-distributed
             probe_result: {}
             verdict: {:?}
             notes: {}
",
            std::process::Command::new("hostname")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            std::process::Command::new("uname")
                .arg("-r")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
                .unwrap_or_else(|_| "unknown".to_string()),
            if std::path::Path::new("/dev/kvm").exists() {
                "present"
            } else {
                "absent"
            },
            if std::path::Path::new("/dev/fuse").exists() {
                "present"
            } else {
                "absent"
            },
            report.probe.probe_result,
            report.verdict,
            report.notes.join("; "),
        );
        std::fs::write(&env_path, &env_facts).expect("write env");
        eprintln!("Validation written to {validation_dir}");
    }
}
