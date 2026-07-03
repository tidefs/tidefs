// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use tidefs_validation::receipt_bound_reclaim_runtime::{
    build_receipt_bound_reclaim_evidence_manifest, run_receipt_bound_obsolete_location_trim_gate,
    RECEIPT_BOUND_RECLAIM_ARTIFACT, RECEIPT_BOUND_RECLAIM_ROW_ID,
    RECEIPT_BOUND_RECLAIM_SOURCE_LABEL,
};

#[derive(Debug)]
struct Args {
    row: String,
    output_dir: PathBuf,
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

    let manifest = build_receipt_bound_reclaim_evidence_manifest(
        &evidence,
        &artifact_json,
        workflow_run_id(),
        source_ref(),
        generated_at(),
        workflow_name(),
    );
    manifest.verify_artifact_digest(&args.output_dir)?;
    let manifest_path = args.output_dir.join("evidence-manifest.json");
    fs::write(&manifest_path, manifest.to_json_pretty()?)?;

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

fn workflow_name() -> String {
    env::var("GITHUB_WORKFLOW").unwrap_or_else(|_| RECEIPT_BOUND_RECLAIM_SOURCE_LABEL.into())
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
    env::var("TIDEFS_GENERATED_AT")
        .or_else(|_| env::var("GITHUB_EVENT_CREATED_AT"))
        .unwrap_or_else(|_| {
            command_output("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
        })
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(program).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}
