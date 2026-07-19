// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Validate a mounted acknowledgment runtime report and companion manifest.

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use tidefs_validation::storage_intent_ack_runtime::validate_ack_runtime_evidence_json;

const USAGE: &str =
    "usage: storage-intent-ack-runtime-report-validation <report.json> <manifest.json>";

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args_os().skip(1);
    let report_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| USAGE.to_string())?;
    let manifest_path = args
        .next()
        .map(PathBuf::from)
        .ok_or_else(|| USAGE.to_string())?;
    if args.next().is_some() {
        return Err(USAGE.to_string());
    }
    let report = fs::read(&report_path)
        .map_err(|error| format!("read report `{}`: {error}", report_path.display()))?;
    let manifest = fs::read(&manifest_path)
        .map_err(|error| format!("read manifest `{}`: {error}", manifest_path.display()))?;
    validate_ack_runtime_evidence_json(&report, &manifest).map_err(|error| error.to_string())?;
    eprintln!(
        "validated mounted acknowledgment runtime report={} manifest={}",
        report_path.display(),
        manifest_path.display()
    );
    Ok(())
}
