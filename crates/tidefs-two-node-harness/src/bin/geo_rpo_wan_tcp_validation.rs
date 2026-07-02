// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use tidefs_two_node_harness::artifact_manifest::{
    EvidenceArtifactManifest, EvidenceOutcome, GeoRpoWanTcpManifestInput, GitHubActionsArtifactRef,
    GEO_PERFORMANCE_FAULT_EVIDENCE_CLASS, GEO_POLICY_TRANSPORT_EVIDENCE_CLASS,
    GEO_TEMPORAL_RECOVERY_EVIDENCE_CLASS,
};
use tidefs_two_node_harness::geo_rpo::{
    run_geo_rpo_child, run_geo_rpo_wan_tcp_validation, GeoRpoWanTcpReport, GEO_RPO_ARTIFACT_NAME,
    GEO_RPO_VALIDATION_TEST_NAME, GEO_RPO_WORKFLOW_NAME,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("tidefs-geo-rpo-wan-tcp-validation: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args = env::args().collect::<Vec<_>>();
    if run_geo_rpo_child(&args)? {
        return Ok(());
    }

    let report = run_geo_rpo_wan_tcp_validation()?;
    if !report.success {
        return Err("geo-RPO WAN/TCP report did not satisfy required rows".to_string());
    }

    let report_json = serde_json::to_string_pretty(&report)
        .map_err(|error| format!("serialize geo-RPO report: {error}"))?;
    maybe_write_evidence(&report, &report_json)?;

    println!("GEO_RPO_WAN_TCP_REPORT_BEGIN");
    println!("{report_json}");
    println!("GEO_RPO_WAN_TCP_REPORT_END");
    Ok(())
}

fn maybe_write_evidence(report: &GeoRpoWanTcpReport, report_json: &str) -> Result<(), String> {
    let Ok(output_dir) = env::var("TIDEFS_GEO_RPO_EVIDENCE_DIR") else {
        return Ok(());
    };
    let output_dir = PathBuf::from(output_dir);
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("create evidence dir {}: {error}", output_dir.display()))?;

    let generated_at = required_env("TIDEFS_GENERATED_AT")?;
    let source_ref = required_env("TIDEFS_GEO_RPO_SOURCE_REF")
        .or_else(|_| required_env("GITHUB_SHA"))
        .or_else(|_| required_env("GITHUB_REF"))?;
    let workflow = env::var("GITHUB_WORKFLOW").unwrap_or_else(|_| GEO_RPO_WORKFLOW_NAME.into());
    let run_id = required_env("GITHUB_RUN_ID")?;
    let run_attempt = required_env("GITHUB_RUN_ATTEMPT")?;
    let artifact_name = env::var("TIDEFS_GEO_RPO_GITHUB_ARTIFACT_NAME")
        .unwrap_or_else(|_| GEO_RPO_ARTIFACT_NAME.to_string());
    validate_artifact_name(&artifact_name)?;
    let run_url = env::var("TIDEFS_GEO_RPO_GITHUB_RUN_URL").unwrap_or_else(|_| {
        let server =
            env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".to_string());
        let repo = env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "tidefs/tidefs".to_string());
        format!("{server}/{repo}/actions/runs/{run_id}")
    });

    for target in evidence_targets() {
        let artifact = evidence_document(report, target.evidence_class, report_json)?;
        let artifact_path = output_dir.join(target.file_name);
        fs::write(&artifact_path, &artifact)
            .map_err(|error| format!("write {}: {error}", artifact_path.display()))?;

        let manifest = EvidenceArtifactManifest::geo_rpo_wan_tcp(GeoRpoWanTcpManifestInput {
            evidence_class: target.evidence_class,
            artifact_path: target.claim_artifact_path,
            artifact_bytes: artifact.as_bytes(),
            github_actions: GitHubActionsArtifactRef {
                workflow: &workflow,
                run_id: &run_id,
                run_attempt: &run_attempt,
                run_url: &run_url,
                artifact_name: &artifact_name,
            },
            source_ref: &source_ref,
            generated_at: &generated_at,
            outcome: EvidenceOutcome::Pass,
            blocking_issues: Vec::new(),
        })
        .map_err(|error| error.to_string())?;
        let manifest_path = output_dir.join(target.manifest_file_name);
        manifest
            .write_json_path(&manifest_path)
            .map_err(|error| error.to_string())?;

        println!(
            "GEO_RPO_EVIDENCE_ARTIFACT={} class={}",
            artifact_path.display(),
            target.evidence_class
        );
        println!(
            "GEO_RPO_EVIDENCE_MANIFEST={} class={}",
            manifest_path.display(),
            target.evidence_class
        );
    }

    Ok(())
}

struct EvidenceTarget {
    evidence_class: &'static str,
    file_name: &'static str,
    manifest_file_name: &'static str,
    claim_artifact_path: &'static str,
}

fn evidence_targets() -> &'static [EvidenceTarget] {
    &[
        EvidenceTarget {
            evidence_class: GEO_POLICY_TRANSPORT_EVIDENCE_CLASS,
            file_name: "geo-policy-transport-evidence.json",
            manifest_file_name: "geo-policy-transport-evidence.manifest.json",
            claim_artifact_path:
                "validation/artifacts/storage-intent/geo-policy-transport-evidence.json",
        },
        EvidenceTarget {
            evidence_class: GEO_TEMPORAL_RECOVERY_EVIDENCE_CLASS,
            file_name: "geo-temporal-recovery-evidence.json",
            manifest_file_name: "geo-temporal-recovery-evidence.manifest.json",
            claim_artifact_path:
                "validation/artifacts/storage-intent/geo-temporal-recovery-evidence.json",
        },
        EvidenceTarget {
            evidence_class: GEO_PERFORMANCE_FAULT_EVIDENCE_CLASS,
            file_name: "geo-performance-fault-rows.json",
            manifest_file_name: "geo-performance-fault-rows.manifest.json",
            claim_artifact_path:
                "validation/artifacts/storage-intent/geo-performance-fault-rows.json",
        },
    ]
}

fn evidence_document(
    report: &GeoRpoWanTcpReport,
    evidence_class: &str,
    report_json: &str,
) -> Result<String, String> {
    let focus_rows: Vec<_> = report
        .rows
        .iter()
        .filter(|row| match evidence_class {
            GEO_POLICY_TRANSPORT_EVIDENCE_CLASS => row.name == "wan-tcp-lag-freshness",
            GEO_TEMPORAL_RECOVERY_EVIDENCE_CLASS => {
                row.name == "wan-tcp-lag-freshness"
                    || row.name == "catch-up-after-partition"
                    || row.name == "stale-clock-refusal"
            }
            GEO_PERFORMANCE_FAULT_EVIDENCE_CLASS => {
                row.name == "loss-jitter-retry"
                    || row.name == "bandwidth-clamp"
                    || row.name == "partition-degraded-refusal"
                    || row.name == "stale-clock-refusal"
            }
            _ => false,
        })
        .collect();
    let document = json!({
        "test": GEO_RPO_VALIDATION_TEST_NAME,
        "claim_id": report.claim_id,
        "evidence_class": evidence_class,
        "validation_tier": report.validation_tier,
        "carrier": report.carrier,
        "rdma_absent": report.rdma_absent,
        "process_model": report.process_model,
        "focus_rows": focus_rows,
        "all_rows": &report.rows,
        "receiver": &report.receiver,
        "success": report.success,
        "residual_risk": report.residual_risk,
        "full_report_json_blake3": blake3_hex(report_json.as_bytes()),
    });
    serde_json::to_string_pretty(&document)
        .map_err(|error| format!("serialize evidence document: {error}"))
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required when evidence output is enabled"))
}

fn validate_artifact_name(value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('$')
        || value.contains('`')
        || path.is_absolute()
    {
        return Err("TIDEFS_GEO_RPO_GITHUB_ARTIFACT_NAME must be a plain artifact name".into());
    }
    Ok(())
}

fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}
