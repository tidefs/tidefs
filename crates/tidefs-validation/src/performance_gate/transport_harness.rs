//! Transport budget harness for multi-node performance gate (REL-MN-011).
//!
//! Invokes the two-node harness transport budget measurement via `cargo test`
//! and parses the JSON KPI output.  Discloses carrier mode (loopback, TCP, RDMA).

use super::benchmark_harness::BenchmarkResult;
use super::validation_tier::ValidationTier;
use super::gate_entry::MeasuredKpi;
use std::process::Command;

pub struct TransportHarness {
    pub repo_root: String,
    pub target_dir: String,
}

impl TransportHarness {
    pub fn new(repo_root: impl Into<String>, target_dir: impl Into<String>) -> Self {
        TransportHarness {
            repo_root: repo_root.into(),
            target_dir: target_dir.into(),
        }
    }

    /// Run the two-node harness transport budget measurement.
    pub fn run(&self) -> BenchmarkResult {
        let subject = "transport";
        let tier = ValidationTier::MultiProcessDistributed;

        let result = Command::new("cargo")
            .arg("test")
            .arg("-p")
            .arg("tidefs-two-node-harness")
            .arg("--test")
            .arg("transport_budget")
            .arg("transport_budget_measure")
            .arg("--")
            .arg("--nocapture")
            .arg("--ignored")
            .env("CARGO_TARGET_DIR", &self.target_dir)
            .env("CARGO_BUILD_JOBS", "1")
            .env("RUST_TEST_THREADS", "1")
            .current_dir(&self.repo_root)
            .output();

        match result {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let executed = output.status.success();

                let mut kpis = if executed {
                    parse_transport_budget_json(&stdout, subject, &mut String::new())
                } else {
                    Vec::new()
                };

                let mut carrier_info = String::new();
                let _carrier_kpis = if executed {
                    parse_transport_budget_json(&stdout, subject, &mut carrier_info)
                } else {
                    Vec::new()
                };

                // Add carrier mode disclosure as a KPI note.
                if executed && !carrier_info.is_empty() {
                    kpis.push(MeasuredKpi {
                        ref_id: "kpi.carrier".into(),
                        name: format!("{subject}/carrier-mode"),
                        value: 0.0,
                        unit: carrier_info,
                        passed: None,
                        percentile: None,
                    });
                }

                let duration = if executed && !kpis.is_empty() {
                    kpis.iter().map(|k| k.value).sum::<f64>()
                } else {
                    0.0
                };

                let desc = if executed {
                    format!(
                        "two-node harness transport budget: {} KPIs collected",
                        kpis.len()
                    )
                } else {
                    format!(
                        "transport budget measurement failed: exit={}",
                        output.status.code().unwrap_or(-1)
                    )
                };

                BenchmarkResult {
                    subject: subject.to_string(),
                    description: desc,
                    executed,
                    exit_code: Some(output.status.code().unwrap_or(-1)),
                    duration_secs: duration,
                    kpis,
                    validation_tier: tier,
                    stdout_tail: tail_str(&stdout, 500),
                    stderr_tail: tail_str(&stderr, 200),
                }
            }
            Err(e) => BenchmarkResult::refused(
                subject,
                format!("cargo test transport_budget failed: {e}"),
                tier,
            ),
        }
    }
}

/// Parse JSON output wrapped in TRANSPORT_BUDGET_JSON_BEGIN/END markers.
/// Returns KPIs; if `carrier_info_out` is non-empty on entry, fills it with
/// the carrier mode disclosure string.
fn parse_transport_budget_json(
    stdout: &str,
    subject: &str,
    carrier_info_out: &mut String,
) -> Vec<MeasuredKpi> {
    let mut kpis = Vec::new();

    // Extract JSON block
    let begin = match stdout.find("TRANSPORT_BUDGET_JSON_BEGIN") {
        Some(p) => p + "TRANSPORT_BUDGET_JSON_BEGIN".len(),
        None => return kpis,
    };
    let end = match stdout[begin..].find("TRANSPORT_BUDGET_JSON_END") {
        Some(p) => begin + p,
        None => return kpis,
    };
    let json_block = stdout[begin..end].trim();

    let val: serde_json::Value = match serde_json::from_str(json_block) {
        Ok(v) => v,
        Err(_) => return kpis,
    };

    // Extract carrier mode disclosure
    let carrier = val
        .get("carrier")
        .and_then(|c| c.as_str())
        .unwrap_or("unknown");
    let carrier_mode = val
        .pointer("/carrier_disclosure/mode")
        .and_then(|m| m.as_str())
        .unwrap_or("unknown");
    let tcp_avail = val
        .pointer("/carrier_disclosure/tcp_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let rdma_avail = val
        .pointer("/carrier_disclosure/rdma_available")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    *carrier_info_out =
        format!("carrier={carrier} mode={carrier_mode} tcp={tcp_avail} rdma={rdma_avail}");

    // Extract per-payload-size measurements as KPIs
    if let Some(measurements) = val.get("measurements").and_then(|m| m.as_array()) {
        for m in measurements {
            let size = m
                .get("payload_size_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let lat = m
                .get("avg_latency_us")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let tp = m
                .get("throughput_mb_s")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);

            kpis.push(MeasuredKpi {
                ref_id: format!("kpi.latency.transport.{size}B"),
                name: format!("{subject}/latency-us-{size}B"),
                value: lat,
                unit: "us".into(),
                passed: None,
                percentile: None,
            });
            kpis.push(MeasuredKpi {
                ref_id: format!("kpi.throughput.transport.{size}B"),
                name: format!("{subject}/throughput-mb_s-{size}B"),
                value: tp,
                unit: "MB/s".into(),
                passed: None,
                percentile: None,
            });
        }
    }

    // Add aggregate throughput across all sizes
    let agg_tp = kpis
        .iter()
        .filter(|k| k.unit == "MB/s")
        .map(|k| k.value)
        .sum::<f64>();
    if agg_tp > 0.0 {
        kpis.push(MeasuredKpi {
            ref_id: "kpi.throughput.transport.aggregate".into(),
            name: format!("{subject}/throughput-mb_s-aggregate"),
            value: agg_tp,
            unit: "MB/s".into(),
            passed: None,
            percentile: None,
        });
    }

    kpis
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
    fn parse_budget_json() {
        let json = serde_json::json!({
            "harness": "tidefs-two-node-harness",
            "carrier": "loopback-deterministic",
            "carrier_disclosure": {
                "mode": "loopback",
                "tcp_available": false,
                "rdma_available": false,
                "note": "Deterministic in-memory loopback"
            },
            "measurements": [
                {
                    "payload_size_bytes": 256,
                    "round_trips": 10,
                    "avg_latency_us": 42.0,
                    "total_bytes_per_rt": 512,
                    "throughput_mb_s": 11.6
                }
            ],
            "kpi_version": 1
        });
        let mut carrier = String::new();
        let stdout = format!(
            "TRANSPORT_BUDGET_JSON_BEGIN\n{}\nTRANSPORT_BUDGET_JSON_END",
            serde_json::to_string_pretty(&json).unwrap()
        );
        let kpis = parse_transport_budget_json(&stdout, "transport", &mut carrier);
        assert!(!kpis.is_empty());
        assert!(carrier.contains("loopback"));
        assert!(carrier.contains("tcp=false"));
    }

    #[test]
    fn parse_no_json() {
        let mut c = String::new();
        assert!(parse_transport_budget_json("", "t", &mut c).is_empty());
    }
}
