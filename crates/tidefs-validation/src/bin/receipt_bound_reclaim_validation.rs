// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tidefs_validation::receipt_bound_reclaim_runtime::{
    run_receipt_bound_obsolete_location_trim_gate, RECEIPT_BOUND_RECLAIM_ARTIFACT,
    RECEIPT_BOUND_RECLAIM_ROW_ID,
};

#[derive(Debug)]
struct Args {
    row: String,
    output_dir: PathBuf,
}

#[derive(Serialize)]
struct EvidenceManifest {
    manifest_version: u8,
    claim_id: String,
    evidence_class: String,
    validation_tier: String,
    source: String,
    scope: String,
    artifact_path: String,
    content_digest: String,
    run_id: String,
    source_ref: String,
    outcome: String,
    residual_risk: String,
    generated_at: String,
    blocking_issues: Vec<String>,
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("receipt-bound reclaim validation failed: {err}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(env::args().skip(1))?;
    if args.row != RECEIPT_BOUND_RECLAIM_ROW_ID {
        return Err(format!(
            "unsupported row '{}'; expected '{}'",
            args.row, RECEIPT_BOUND_RECLAIM_ROW_ID
        )
        .into());
    }

    fs::create_dir_all(&args.output_dir)?;
    let evidence = run_receipt_bound_obsolete_location_trim_gate();
    let artifact_path = args.output_dir.join(RECEIPT_BOUND_RECLAIM_ARTIFACT);
    let artifact_json = serde_json::to_vec_pretty(&evidence)?;
    fs::write(&artifact_path, &artifact_json)?;

    let digest = blake3::hash(&artifact_json);
    let manifest = EvidenceManifest {
        manifest_version: 3,
        claim_id: "receipt-bound-reclaim.physical-drain-runtime-row.v1".to_string(),
        evidence_class: "receipt-bound-reclaim-runtime-row".to_string(),
        validation_tier: "github-actions-runtime-harness".to_string(),
        source: workflow_name(),
        scope: format!(
            "row={} issue=#1528 parent=#676 disposition={} artifact={}",
            evidence.row_id,
            evidence.parent_tracker_disposition,
            RECEIPT_BOUND_RECLAIM_ARTIFACT
        ),
        artifact_path: relative_artifact_path(&args.output_dir, &artifact_path),
        content_digest: format!("blake3:{digest}"),
        run_id: workflow_run_id(),
        source_ref: source_ref(),
        outcome: if evidence.passed { "pass" } else { "product-fail" }.to_string(),
        residual_risk: "This row proves the receipt-bound dead-object queue replay into the physical drain boundary with a SegmentFreer observer only; it is not mounted FUSE, kernel, xfstests, RDMA, whole allocator, or release-candidate evidence.".to_string(),
        generated_at: generated_at(),
        blocking_issues: Vec::new(),
    };
    let manifest_path = args.output_dir.join("evidence-manifest.json");
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    evidence.assert_passed()?;
    println!(
        "receipt-bound reclaim row '{}' passed; artifact={}",
        evidence.row_id,
        artifact_path.display()
    );
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut row = RECEIPT_BOUND_RECLAIM_ROW_ID.to_string();
    let mut output_dir = PathBuf::from(".");
    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--row" => {
                row = iter
                    .next()
                    .ok_or_else(|| "--row requires a value".to_string())?;
            }
            "--output-dir" => {
                output_dir = iter
                    .next()
                    .map(PathBuf::from)
                    .ok_or_else(|| "--output-dir requires a value".to_string())?;
            }
            "--help" | "-h" => {
                return Err(format!(
                    "usage: receipt-bound-reclaim-validation --row {RECEIPT_BOUND_RECLAIM_ROW_ID} --output-dir DIR"
                ));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args { row, output_dir })
}

fn relative_artifact_path(output_dir: &Path, artifact_path: &Path) -> String {
    artifact_path
        .strip_prefix(output_dir)
        .unwrap_or(artifact_path)
        .display()
        .to_string()
}

fn workflow_name() -> String {
    env::var("GITHUB_WORKFLOW").unwrap_or_else(|_| "local-receipt-bound-reclaim-validation".into())
}

fn workflow_run_id() -> String {
    match (env::var("GITHUB_RUN_ID"), env::var("GITHUB_RUN_ATTEMPT")) {
        (Ok(run_id), Ok(run_attempt)) => format!("{run_id}/{run_attempt}"),
        (Ok(run_id), Err(_)) => run_id,
        _ => "local".to_string(),
    }
}

fn source_ref() -> String {
    env::var("GITHUB_SHA")
        .or_else(|_| env::var("GITHUB_REF_NAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

fn generated_at() -> String {
    env::var("TIDEFS_GENERATED_AT").unwrap_or_else(|_| "unknown".to_string())
}
