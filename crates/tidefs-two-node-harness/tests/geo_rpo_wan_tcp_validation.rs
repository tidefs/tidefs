// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::collections::BTreeSet;
use std::fs;
use std::process::Command;

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_tidefs-geo-rpo-wan-tcp-validation");

#[test]
fn geo_rpo_wan_tcp_binary_emits_runtime_artifacts() {
    let evidence_dir = tempfile::tempdir().expect("evidence tempdir");
    let output = Command::new(BIN)
        .env("TIDEFS_GEO_RPO_EVIDENCE_DIR", evidence_dir.path())
        .env("TIDEFS_GENERATED_AT", "2026-07-02T09:00:00Z")
        .env("TIDEFS_GEO_RPO_SOURCE_REF", "refs/heads/test-geo-rpo")
        .env("TIDEFS_GEO_RPO_GITHUB_RUN_URL", github_run_url())
        .env("TIDEFS_GEO_RPO_GITHUB_ARTIFACT_NAME", artifact_name())
        .env("GITHUB_WORKFLOW", "Geo RPO WAN TCP")
        .env("GITHUB_RUN_ID", github_run_id())
        .env("GITHUB_RUN_ATTEMPT", "1")
        .output()
        .expect("run geo RPO validation binary");

    assert!(
        output.status.success(),
        "geo RPO binary failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
    let report = extract_report(&stdout);
    assert_eq!(report["success"], true);
    assert_eq!(report["carrier"], "tcp");
    assert_eq!(report["rdma_absent"], true);
    assert_eq!(report["receiver"]["rdma_sessions"], 0);
    assert_eq!(report["receiver"]["tcp_sessions"], 1);

    let rows = report["rows"].as_array().expect("rows array");
    let row_names = rows
        .iter()
        .map(|row| row["name"].as_str().expect("row name"))
        .collect::<BTreeSet<_>>();
    for required in [
        "wan-tcp-lag-freshness",
        "loss-jitter-retry",
        "bandwidth-clamp",
        "partition-degraded-refusal",
        "catch-up-after-partition",
        "stale-clock-refusal",
    ] {
        assert!(row_names.contains(required), "missing row {required}");
    }

    let stale_clock = rows
        .iter()
        .find(|row| row["name"] == "stale-clock-refusal")
        .expect("stale clock row");
    assert_eq!(stale_clock["runtime_state"], "refused-stale-clock");
    assert_eq!(stale_clock["refusal_visible"], true);

    let partition = rows
        .iter()
        .find(|row| row["name"] == "partition-degraded-refusal")
        .expect("partition row");
    assert_eq!(partition["degraded_visible"], true);
    assert_eq!(partition["refusal_visible"], true);

    for evidence_class in [
        (
            "geo-policy-transport-evidence",
            "storage-intent-geo-policy-transport-evidence",
        ),
        (
            "geo-temporal-recovery-evidence",
            "storage-intent-geo-temporal-recovery-evidence",
        ),
        (
            "geo-performance-fault-rows",
            "storage-intent-geo-performance-fault-rows",
        ),
    ] {
        assert_geo_manifest(evidence_dir.path(), evidence_class.0, evidence_class.1);
    }
}

fn extract_report(stdout: &str) -> Value {
    let report_json = stdout
        .split("GEO_RPO_WAN_TCP_REPORT_BEGIN")
        .nth(1)
        .expect("report begin marker")
        .split("GEO_RPO_WAN_TCP_REPORT_END")
        .next()
        .expect("report end marker")
        .trim();
    serde_json::from_str(report_json).expect("parse report JSON")
}

fn assert_geo_manifest(evidence_dir: &std::path::Path, stem: &str, evidence_class: &str) {
    let artifact_path = evidence_dir.join(format!("{stem}.json"));
    let manifest_path = evidence_dir.join(format!("{stem}.manifest.json"));
    let artifact = fs::read_to_string(&artifact_path).expect("artifact JSON");
    let manifest: Value =
        serde_json::from_str(&fs::read_to_string(&manifest_path).expect("manifest JSON"))
            .expect("parse manifest JSON");

    assert_eq!(manifest["claim_id"], "storage.intent.geo_async_rpo.v1");
    assert_eq!(manifest["evidence_class"], evidence_class);
    assert_eq!(manifest["validation_tier"], "multi-process-distributed");
    assert_eq!(manifest["outcome"], "pass");
    assert_eq!(
        manifest["run_id"].as_str().expect("manifest run_id"),
        format!(
            "github-actions:{}:attempt:1:artifact:{}",
            github_run_id(),
            artifact_name()
        )
    );
    assert_eq!(
        manifest["artifact_path"]
            .as_str()
            .expect("manifest artifact_path"),
        format!("validation/artifacts/storage-intent/{stem}.json")
    );
    assert!(manifest["content_digest"]
        .as_str()
        .expect("content digest")
        .starts_with("blake3:"));
    assert!(artifact.contains("\"rdma_absent\": true"));
    assert!(artifact.contains("\"success\": true"));
}

fn github_run_id() -> &'static str {
    "28298370275"
}

fn github_run_url() -> &'static str {
    "https://github.com/tidefs/tidefs/actions/runs/28298370275"
}

fn artifact_name() -> &'static str {
    "geo-rpo-wan-tcp-validation"
}
