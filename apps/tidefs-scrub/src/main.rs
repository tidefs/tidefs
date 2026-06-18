// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! tidefs-scrub — object-store data integrity scrub and verification tool.
//!
//! Walks every object key in a local TideFS store, verifies the recorded
//! payload checksum, validates compression frame headers, and reports
//! inconsistencies.
//!
//! Usage:
//!   tidefs-scrub check <store_root> [--json] [--unreachable=count|warn|fail]
//!   tidefs-scrub scan  <store_root>
//!
//! Exit codes:
//!   0 — clean: no inconsistencies found
//!   1 — inconsistencies found
//!   2 — invalid invocation
//!   3 — backend read failure (store could not be opened or walked)

mod scrub;

use std::env;
use std::process;
use std::sync::Arc;

use scrub::{ScrubWalker, UnreachableObjectPolicy};
use tidefs_local_object_store::{LocalObjectStore, StoreOptions};
use tidefs_scrub::{Blake3Verifier, ScrubWorker, StoreTraverser};

// ── check subcommand ──────────────────────────────────────────────────

struct CheckArgs {
    store_root: String,
    json_output: bool,
    unreachable_policy: UnreachableObjectPolicy,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!(
            "usage: tidefs-scrub check <store_root> [--json] [--unreachable=count|warn|fail]"
        );
        eprintln!("       tidefs-scrub scan <store_root>");
        process::exit(2);
    }

    let cmd = &args[1];
    match cmd.as_str() {
        "scan" => run_scan(&args),
        "check" => run_check(&args),
        "--help" | "-h" | "help" => {
            print_usage();
            process::exit(0);
        }
        _ => {
            eprintln!("tidefs-scrub: unknown command '{cmd}'");
            eprintln!(
                "usage: tidefs-scrub check <store_root> [--json] [--unreachable=count|warn|fail]"
            );
            eprintln!("       tidefs-scrub scan <store_root>");
            process::exit(2);
        }
    }
}

fn run_check(args: &[String]) {
    let check_args = match parse_check_args(args) {
        Ok(args) => args,
        Err(message) => {
            eprintln!("{message}");
            eprintln!(
                "usage: tidefs-scrub check <store_root> [--json] [--unreachable=count|warn|fail]"
            );
            process::exit(2);
        }
    };

    let walker_result = if check_args.unreachable_policy == UnreachableObjectPolicy::default() {
        ScrubWalker::open(&check_args.store_root)
    } else {
        ScrubWalker::open_with_unreachable_policy(
            &check_args.store_root,
            check_args.unreachable_policy,
        )
    };
    let walker = match walker_result {
        Ok(w) => w,
        Err(e) => {
            eprintln!(
                "tidefs-scrub: failed to open store at {}: {}",
                check_args.store_root, e
            );
            process::exit(3);
        }
    };

    let report = match walker.walk() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("tidefs-scrub: walk failed: {e}");
            process::exit(3);
        }
    };

    if check_args.json_output {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("tidefs-scrub: failed to serialize report: {e}");
                process::exit(3);
            }
        }
    } else {
        println!("{}", report.text_summary());
    }

    process::exit(report.exit_code());
}

// ── scan subcommand ───────────────────────────────────────────────────

fn run_scan(args: &[String]) {
    if args.len() < 3 {
        eprintln!("tidefs-scrub scan: missing <store_root> argument");
        eprintln!("usage: tidefs-scrub scan <store_root>");
        process::exit(2);
    }

    let store_root = &args[2];

    let opts = StoreOptions {
        repair_torn_tail: false,
        ..Default::default()
    };

    let store =
        match LocalObjectStore::open_read_only_with_options(std::path::Path::new(store_root), opts)
        {
            Ok(Some(s)) => s,
            Ok(None) => {
                eprintln!("tidefs-scrub scan: store root does not exist: {store_root}");
                process::exit(3);
            }
            Err(e) => {
                eprintln!("tidefs-scrub scan: failed to open store at {store_root}: {e}");
                process::exit(3);
            }
        };

    let traverser = StoreTraverser::new(store);
    let worker = ScrubWorker::new(Arc::new(traverser), Arc::new(Blake3Verifier));
    let summary = worker.run();

    println!("{}", summary.text_summary());

    process::exit(if summary.is_clean() { 0 } else { 1 });
}

// ── argument parsing ──────────────────────────────────────────────────

fn parse_check_args(args: &[String]) -> Result<CheckArgs, String> {
    if args.len() < 3 {
        return Err("tidefs-scrub check: missing <store_root> argument".to_string());
    }

    let mut json_output = false;
    let mut unreachable_policy = UnreachableObjectPolicy::default();

    for arg in &args[3..] {
        if arg == "--json" {
            json_output = true;
        } else if let Some(value) = arg.strip_prefix("--unreachable=") {
            unreachable_policy = UnreachableObjectPolicy::parse(value)?;
        } else {
            return Err(format!("tidefs-scrub check: unknown option '{arg}'"));
        }
    }

    Ok(CheckArgs {
        store_root: args[2].clone(),
        json_output,
        unreachable_policy,
    })
}

fn print_usage() {
    println!("tidefs-scrub — TideFS object-store integrity scrub tool");
    println!();
    println!("Usage:");
    println!("  tidefs-scrub check <store_root> [--json] [--unreachable=count|warn|fail]");
    println!("  tidefs-scrub scan  <store_root>");
    println!();
    println!("  check        Walk every object in the store and verify checksums,");
    println!("               compression frames, and object reachability.");
    println!("  scan         Walk every object, compute BLAKE3 checksum tree root,");
    println!("               compare against stored digests, report mismatches.");
    println!("  --json       Emit machine-readable JSON instead of text summary.");
    println!("  --unreachable=count|warn|fail");
    println!("               Treat unreachable/reclaimable objects as metadata,");
    println!("               warning findings, or error findings.");
    println!();
    println!("Exit codes:");
    println!("  0  clean — no inconsistencies found");
    println!("  1  inconsistencies found");
    println!("  2  invalid invocation");
    println!("  3  backend read failure");
}
