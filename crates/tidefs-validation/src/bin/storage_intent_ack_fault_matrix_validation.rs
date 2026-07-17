// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note

use std::collections::BTreeMap;
use std::env;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process;
use std::thread;
use std::time::Duration;
use tidefs_validation::storage_intent_ack_fault_matrix::{
    ensure_qemu_guest, prepare_crash_after_ack, prepare_kill_before_ack, verify_fault_matrix,
    write_manifest_for_report, AckFaultRunProvenance, CRASH_AFTER_ACK_MARKER,
    KILL_BEFORE_ACK_MARKER, REPORT_BEGIN_MARKER, REPORT_END_MARKER,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage("missing command"));
    };
    let options = parse_options(args)?;
    match command.as_str() {
        "guest" => run_guest(&options),
        "manifest" => run_manifest(&options),
        "--help" | "-h" | "help" => {
            println!("{}", usage_text());
            Ok(())
        }
        other => Err(usage(&format!("unknown command `{other}`"))),
    }
}

fn run_guest(options: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(options, &["--phase", "--media"])?;
    let phase = required(options, "--phase")?;
    let media = PathBuf::from(required(options, "--media")?);
    ensure_qemu_guest()?;

    match phase {
        "kill-before-ack" => {
            prepare_kill_before_ack(&media)?;
            println!("{KILL_BEFORE_ACK_MARKER}");
            io::stdout()
                .flush()
                .map_err(|error| format!("flush pre-ack marker: {error}"))?;
            wait_for_host_crash_injection();
        }
        "crash-after-ack" => {
            prepare_crash_after_ack(&media)?;
            println!("{CRASH_AFTER_ACK_MARKER}");
            io::stdout()
                .flush()
                .map_err(|error| format!("flush post-ack marker: {error}"))?;
            wait_for_host_crash_injection();
        }
        "verify" => {
            let provenance = AckFaultRunProvenance::from_qemu_guest()?;
            let report = verify_fault_matrix(&media, provenance)?;
            let report_json = serde_json::to_string_pretty(&report)
                .map_err(|error| format!("serialize acknowledgment fault report: {error}"))?;
            println!("{REPORT_BEGIN_MARKER}");
            println!("{report_json}");
            println!("{REPORT_END_MARKER}");
            io::stdout()
                .flush()
                .map_err(|error| format!("flush acknowledgment fault report: {error}"))?;
            if report.is_pass() {
                Ok(())
            } else {
                Err(format!(
                    "acknowledgment fault matrix reported {} product failure(s)",
                    report.summary.product_failed
                ))
            }
        }
        other => Err(usage(&format!("unknown guest phase `{other}`"))),
    }
}

fn run_manifest(options: &BTreeMap<String, String>) -> Result<(), String> {
    reject_unknown(options, &["--artifact-root", "--report", "--manifest"])?;
    let artifact_root = PathBuf::from(required(options, "--artifact-root")?);
    let report = PathBuf::from(required(options, "--report")?);
    let manifest = PathBuf::from(required(options, "--manifest")?);
    let written = write_manifest_for_report(report, artifact_root, &manifest)?;
    println!(
        "acknowledgment fault manifest validated: outcome={} artifact_path={} manifest={}",
        written.outcome.label(),
        written.artifact_path,
        manifest.display()
    );
    if written.outcome.is_pass() {
        Ok(())
    } else {
        Err(format!(
            "acknowledgment fault manifest outcome is {}",
            written.outcome.label()
        ))
    }
}

fn wait_for_host_crash_injection() -> ! {
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

fn parse_options(args: impl Iterator<Item = String>) -> Result<BTreeMap<String, String>, String> {
    let mut options = BTreeMap::new();
    let mut args = args.peekable();
    while let Some(option) = args.next() {
        if !option.starts_with("--") {
            return Err(usage(&format!("unexpected argument `{option}`")));
        }
        let Some(value) = args.next() else {
            return Err(usage(&format!("option `{option}` requires a value")));
        };
        if value.starts_with("--") {
            return Err(usage(&format!("option `{option}` requires a value")));
        }
        if options.insert(option.clone(), value).is_some() {
            return Err(usage(&format!("option `{option}` was supplied twice")));
        }
    }
    Ok(options)
}

fn required<'a>(options: &'a BTreeMap<String, String>, name: &str) -> Result<&'a str, String> {
    options
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| usage(&format!("missing required option `{name}`")))
}

fn reject_unknown(options: &BTreeMap<String, String>, accepted: &[&str]) -> Result<(), String> {
    if let Some(option) = options
        .keys()
        .find(|option| !accepted.contains(&option.as_str()))
    {
        Err(usage(&format!("unknown option `{option}`")))
    } else {
        Ok(())
    }
}

fn usage(error: &str) -> String {
    format!("{error}\n\n{}", usage_text())
}

fn usage_text() -> &'static str {
    "Usage:\n  storage-intent-ack-fault-matrix-validation guest --phase <kill-before-ack|crash-after-ack|verify> --media <block-device>\n  storage-intent-ack-fault-matrix-validation manifest --artifact-root <dir> --report <json> --manifest <json>"
}
