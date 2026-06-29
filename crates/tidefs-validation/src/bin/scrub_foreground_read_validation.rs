// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::env;
use std::fs;
use std::path::PathBuf;

use tidefs_validation::scrub_foreground_read_runtime::{
    build_evidence_manifest, run_scrub_foreground_read_runtime, SCRUB_FOREGROUND_READ_ROW_ID,
    SCRUB_READ_RUNTIME_ARTIFACT,
};

#[derive(Debug)]
struct Args {
    row: String,
    output_dir: PathBuf,
}

fn main() {
    if let Err(err) = real_main() {
        eprintln!("scrub foreground-read validation failed: {err}");
        std::process::exit(1);
    }
}

fn real_main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args(env::args().skip(1))?;
    if args.row != SCRUB_FOREGROUND_READ_ROW_ID {
        return Err(format!(
            "unsupported row '{}'; expected '{}'",
            args.row, SCRUB_FOREGROUND_READ_ROW_ID
        )
        .into());
    }

    fs::create_dir_all(&args.output_dir)?;
    let command = env::args().collect::<Vec<_>>().join(" ");
    let evidence = run_scrub_foreground_read_runtime(command);
    let artifact_path = args.output_dir.join(SCRUB_READ_RUNTIME_ARTIFACT);
    let artifact_json = serde_json::to_vec_pretty(&evidence)?;
    fs::write(&artifact_path, &artifact_json)?;

    let manifest = build_evidence_manifest(&evidence, &artifact_json);
    let manifest_path = args.output_dir.join("evidence-manifest.json");
    fs::write(&manifest_path, manifest.to_json_pretty()?)?;

    evidence.assert_no_product_or_harness_failure()?;
    println!(
        "scrub foreground-read row '{}' outcome={:?}; artifact={}",
        evidence.row_id,
        evidence.outcome,
        artifact_path.display()
    );
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut row = SCRUB_FOREGROUND_READ_ROW_ID.to_string();
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
                    "usage: scrub_foreground_read_validation --row {SCRUB_FOREGROUND_READ_ROW_ID} --output-dir DIR"
                ));
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Args { row, output_dir })
}
