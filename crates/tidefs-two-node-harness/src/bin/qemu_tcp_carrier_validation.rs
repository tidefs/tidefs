// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![cfg(feature = "qemu")]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use tidefs_two_node_harness::artifact_manifest::{
    ClaimBinding, EvidenceArtifactManifest, EvidenceOutcome, GitHubActionsArtifactRef,
    QemuTcpCarrierManifestInput, TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE,
};
use tidefs_two_node_harness::qemu_carrier::{run_qemu_tcp_state_transfer, QemuTcpCarrierReport};
use tidefs_two_node_harness::{blake3_hash, StateObject};

fn main() {
    if let Err(err) = run() {
        eprintln!("tidefs-two-node-qemu-carrier-validation: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let seed = 42;
    let objects = validation_objects();
    let expected_digest = expected_transfer_digest(&objects);

    let report = run_qemu_tcp_state_transfer(seed, objects)?;
    if report.transfer.transfer_digest != expected_digest {
        return Err(
            "live TCP carrier transfer digest did not match expected payload digest".into(),
        );
    }

    let report_json = report_json(&report);
    maybe_write_evidence(&report, &report_json)?;

    println!("QEMU_TCP_CARRIER_REPORT_BEGIN");
    println!("{report_json}");
    println!("QEMU_TCP_CARRIER_REPORT_END");
    Ok(())
}

fn validation_objects() -> Vec<StateObject> {
    vec![
        StateObject {
            object_key: 1,
            payload: b"qemu tcp carrier control object".to_vec(),
        },
        StateObject {
            object_key: 2,
            payload: vec![0xA5; 12 * 1024],
        },
    ]
}

fn expected_transfer_digest(objects: &[StateObject]) -> [u8; 32] {
    let mut payloads = Vec::new();
    for object in objects {
        payloads.extend_from_slice(&object.payload);
    }
    blake3_hash(&payloads)
}

fn report_json(report: &QemuTcpCarrierReport) -> String {
    format!(
        "{{\"test\":\"tidefs-two-node-qemu-carrier-validation\",\
         \"validation_tier\":\"qemu-guest\",\
         \"carrier\":{},\
         \"qemu_guest_detected\":{},\
         \"sender_node_id\":{},\
         \"receiver_node_id\":{},\
         \"receiver_addr\":{},\
         \"object_count\":{},\
         \"total_bytes\":{},\
         \"chunk_count\":{},\
         \"transfer_digest\":\"{}\"}}",
        json_string(report.carrier),
        report.qemu_guest_detected,
        report.sender_node_id,
        report.receiver_node_id,
        json_string(&report.receiver_addr),
        report.transfer.object_count,
        report.transfer.total_bytes,
        report.transfer.chunk_count,
        hex_digest(&report.transfer.transfer_digest),
    )
}

fn maybe_write_evidence(
    report: &QemuTcpCarrierReport,
    report_json: &str,
) -> Result<Option<(PathBuf, PathBuf)>, String> {
    let Ok(output_dir) = env::var("TIDEFS_TWO_NODE_QEMU_EVIDENCE_DIR") else {
        return Ok(None);
    };
    let output_dir = PathBuf::from(output_dir);
    fs::create_dir_all(&output_dir)
        .map_err(|error| format!("create evidence dir {}: {error}", output_dir.display()))?;

    let report_file_name = env::var("TIDEFS_TWO_NODE_QEMU_REPORT_FILE")
        .unwrap_or_else(|_| "carrier-report.json".to_string());
    validate_relative_file_name("TIDEFS_TWO_NODE_QEMU_REPORT_FILE", &report_file_name)?;
    let report_path = output_dir.join(&report_file_name);
    fs::write(&report_path, report_json)
        .map_err(|error| format!("write carrier report {}: {error}", report_path.display()))?;

    let artifact_path =
        env::var("TIDEFS_TWO_NODE_QEMU_ARTIFACT_PATH").unwrap_or_else(|_| report_file_name.clone());
    let source_ref = required_env("TIDEFS_TWO_NODE_QEMU_SOURCE_REF")
        .or_else(|_| required_env("GITHUB_SHA"))
        .or_else(|_| required_env("GITHUB_REF"))?;
    let generated_at = required_env("TIDEFS_TWO_NODE_QEMU_GENERATED_AT")
        .or_else(|_| required_env("TIDEFS_GENERATED_AT"))?;
    let workflow = required_env("TIDEFS_TWO_NODE_QEMU_GITHUB_WORKFLOW")
        .or_else(|_| required_env("GITHUB_WORKFLOW"))?;
    let run_id = required_env("TIDEFS_TWO_NODE_QEMU_GITHUB_RUN_ID")
        .or_else(|_| required_env("GITHUB_RUN_ID"))?;
    let run_attempt = required_env("TIDEFS_TWO_NODE_QEMU_GITHUB_RUN_ATTEMPT")
        .or_else(|_| required_env("GITHUB_RUN_ATTEMPT"))?;
    let artifact_name = required_env("TIDEFS_TWO_NODE_QEMU_GITHUB_ARTIFACT_NAME")?;
    let run_url = env::var("TIDEFS_TWO_NODE_QEMU_GITHUB_RUN_URL").unwrap_or_else(|_| {
        let server =
            env::var("GITHUB_SERVER_URL").unwrap_or_else(|_| "https://github.com".to_string());
        let repo = env::var("GITHUB_REPOSITORY").unwrap_or_else(|_| "tidefs/tidefs".to_string());
        format!("{server}/{repo}/actions/runs/{run_id}")
    });

    let manifest = EvidenceArtifactManifest::qemu_tcp_carrier(QemuTcpCarrierManifestInput {
        claim_binding: ClaimBinding::NonClaimScope(TWO_NODE_QEMU_TCP_NON_CLAIM_SCOPE),
        artifact_path: &artifact_path,
        artifact_bytes: report_json.as_bytes(),
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
        qemu_guest_detected: report.qemu_guest_detected,
        blocking_issues: Vec::new(),
    })
    .map_err(|error| error.to_string())?;

    let manifest_file_name = env::var("TIDEFS_TWO_NODE_QEMU_MANIFEST_FILE")
        .unwrap_or_else(|_| "carrier-report.manifest.json".to_string());
    validate_relative_file_name("TIDEFS_TWO_NODE_QEMU_MANIFEST_FILE", &manifest_file_name)?;
    let manifest_path = output_dir.join(manifest_file_name);
    manifest
        .write_json_path(&manifest_path)
        .map_err(|error| error.to_string())?;

    println!("QEMU_TCP_CARRIER_EVIDENCE_REPORT={}", report_path.display());
    println!(
        "QEMU_TCP_CARRIER_EVIDENCE_MANIFEST={}",
        manifest_path.display()
    );
    Ok(Some((report_path, manifest_path)))
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("{name} is required when evidence output is enabled"))
}

fn validate_relative_file_name(name: &str, value: &str) -> Result<(), String> {
    let path = Path::new(value);
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value.contains('$')
        || value.contains('`')
        || path.is_absolute()
    {
        return Err(format!("{name} must be a plain relative file name"));
    }
    Ok(())
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn hex_digest(digest: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    hex
}
