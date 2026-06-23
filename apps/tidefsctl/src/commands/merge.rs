// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Manual conflict resolution surface for the receive merge planner.
//!
//! Implements `tidefsctl merge resolve` — the operator-facing CLI for the
//! `manual` merge policy (§5.1 item 5 of `docs/RECEIVE_MERGE_PLANNER_DESIGN.md`).
//!
//! # Workflow
//!
//! 1. A conflict inventory is produced by the merge planner and saved as JSON
//!    (`ConflictInventory::to_json`).
//! 2. The operator loads it and applies per-entry or per-class resolution
//!    instructions via this CLI.
//! 3. `tidefsctl merge resolve` writes a resolved inventory JSON file.
//! 4. The receive path validates the resolved inventory before proceeding.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

use clap::Parser;
use tidefs_local_filesystem::receive_merge_planner::{
    parse_conflict_class, parse_resolution_kind, ReceiveMergeRootIdentity,
    ResolvedConflictInventory,
};

#[derive(Parser, Debug)]
pub enum MergeCommand {
    /// Apply resolution instructions to a conflict inventory
    Resolve {
        /// Path to the conflict inventory JSON file
        #[arg(short = 'i', long = "inventory", value_name = "PATH")]
        inventory: PathBuf,

        /// Per-entry resolution: INDEX:KIND (e.g. "0:keep_local").
        /// May be repeated.  INDEX is 0-based into the inventory entries.
        #[arg(long = "entry", value_name = "INDEX:KIND")]
        entries: Vec<String>,

        /// Per-class resolution: CLASS:KIND (e.g. "inode_identity:keep_remote").
        /// May be repeated.
        #[arg(long = "class", value_name = "CLASS:KIND")]
        classes: Vec<String>,

        /// Target committed-root identity for staleness anchoring.
        /// Format: TXG:GEN:CHECKSUM (decimal or 0x hex).
        #[arg(long = "anchor-target", value_name = "TXG:GEN:CHECKSUM")]
        anchor_target: Option<String>,

        /// Path to write the resolved inventory JSON file.
        /// Writes to stdout when omitted.
        #[arg(short = 'o', long = "output", value_name = "PATH")]
        output: Option<PathBuf>,
    },

    /// Validate a resolved conflict inventory
    Validate {
        /// Path to the resolved inventory JSON file
        #[arg(short = 'i', long = "inventory", value_name = "PATH")]
        inventory: PathBuf,

        /// Current target committed-root identity for staleness check.
        /// Format: TXG:GEN:CHECKSUM (decimal or 0x hex).
        #[arg(long = "current-target", value_name = "TXG:GEN:CHECKSUM")]
        current_target: Option<String>,
    },

    /// Display the contents of a conflict or resolved inventory
    Show {
        /// Path to the inventory JSON file
        #[arg(short = 'i', long = "inventory", value_name = "PATH")]
        inventory: PathBuf,
    },
}

pub fn handle_merge(cmd: MergeCommand) {
    match cmd {
        MergeCommand::Resolve {
            inventory,
            entries,
            classes,
            anchor_target,
            output,
        } => handle_resolve(inventory, entries, classes, anchor_target, output),
        MergeCommand::Validate {
            inventory,
            current_target,
        } => handle_validate(inventory, current_target),
        MergeCommand::Show { inventory } => handle_show(inventory),
    }
}

fn handle_resolve(
    inventory_path: PathBuf,
    entry_specs: Vec<String>,
    class_specs: Vec<String>,
    anchor_target: Option<String>,
    output: Option<PathBuf>,
) {
    let json = read_file_or_stdin(&inventory_path);
    let conflict_inventory =
        match tidefs_local_filesystem::encoding::ConflictInventory::from_json(&json) {
            Ok(inv) => inv,
            Err(e) => {
                eprintln!("error: failed to parse conflict inventory: {e}");
                process::exit(1);
            }
        };

    let target_identity = match anchor_target {
        Some(ref s) => match parse_root_identity(s) {
            Ok(id) => Some(id),
            Err(e) => {
                eprintln!("error: invalid --anchor-target: {e}");
                process::exit(1);
            }
        },
        None => None,
    };

    let mut resolved =
        ResolvedConflictInventory::from_inventory(conflict_inventory, target_identity);

    for spec in &entry_specs {
        match parse_entry_spec(spec, &resolved) {
            Ok((index, decision)) => {
                if let Err(e) = resolved.resolve_entry(index, decision) {
                    eprintln!("error: {e}");
                    process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("error: invalid --entry {spec:?}: {e}");
                process::exit(1);
            }
        }
    }

    for spec in &class_specs {
        match parse_class_spec(spec) {
            Ok((class, decision)) => {
                resolved.resolve_by_class(class, decision);
            }
            Err(e) => {
                eprintln!("error: invalid --class {spec:?}: {e}");
                process::exit(1);
            }
        }
    }

    let output_json = match resolved.to_json() {
        Ok(j) => j,
        Err(e) => {
            eprintln!("error: failed to serialize resolved inventory: {e}");
            process::exit(1);
        }
    };

    if let Some(ref output_path) = output {
        if let Err(e) = fs::write(output_path, &output_json) {
            eprintln!(
                "error: failed to write {}: {e}",
                output_path.display()
            );
            process::exit(1);
        }
        eprintln!(
            "resolved inventory written to {} ({} resolved, {} unresolved)",
            output_path.display(),
            resolved.resolved_count(),
            resolved.unresolved_count()
        );
    } else {
        println!("{output_json}");
    }
}

fn handle_validate(inventory_path: PathBuf, current_target: Option<String>) {
    let json = read_file_or_stdin(&inventory_path);
    let resolved = match ResolvedConflictInventory::from_json(&json) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: failed to parse resolved inventory: {e}");
            process::exit(1);
        }
    };

    if let Err(e) = resolved.validate_all_resolved() {
        eprintln!("error: {e}");
        process::exit(1);
    }

    if let Some(ref target_str) = current_target {
        let current = match parse_root_identity(target_str) {
            Ok(id) => id,
            Err(e) => {
                eprintln!("error: invalid --current-target: {e}");
                process::exit(1);
            }
        };
        if let Err(e) = resolved.validate_not_stale(&current) {
            eprintln!("error: {e}");
            process::exit(1);
        }
    }

    eprintln!(
        "resolved inventory is valid: {} entries, all resolved",
        resolved.entry_count()
    );
}

fn handle_show(inventory_path: PathBuf) {
    let json = read_file_or_stdin(&inventory_path);

    if let Ok(resolved) = ResolvedConflictInventory::from_json(&json) {
        print_resolved_inventory(&resolved);
        return;
    }

    match tidefs_local_filesystem::encoding::ConflictInventory::from_json(&json) {
        Ok(inv) => print_conflict_inventory(&inv),
        Err(e) => {
            eprintln!("error: failed to parse inventory as conflict or resolved: {e}");
            process::exit(1);
        }
    }
}

fn print_conflict_inventory(inv: &tidefs_local_filesystem::encoding::ConflictInventory) {
    println!("Conflict inventory:");
    println!(
        "  common ancestor: txg={} gen={}",
        inv.common_ancestor_transaction_id, inv.common_ancestor_generation
    );
    println!("  entries: {}", inv.len());
    for (i, entry) in inv.entries.iter().enumerate() {
        println!(
            "  [{i}] class={class:?} stream={stream} target={target} divergence={div:?}",
            class = entry.class,
            stream = entry.stream_identity,
            target = entry.target_identity,
            div = entry.divergence,
        );
    }
}

fn print_resolved_inventory(resolved: &ResolvedConflictInventory) {
    println!("Resolved conflict inventory:");
    println!(
        "  common ancestor: txg={} gen={}",
        resolved.inventory.common_ancestor_transaction_id,
        resolved.inventory.common_ancestor_generation
    );
    println!(
        "  entries: {} (resolved: {}, unresolved: {})",
        resolved.entry_count(),
        resolved.resolved_count(),
        resolved.unresolved_count()
    );
    if let Some(ref anchored) = resolved.anchored_at_target_identity {
        println!(
            "  anchored at target: txg={} gen={} checksum={}",
            anchored.transaction_id, anchored.generation, anchored.superblock_checksum
        );
    }
    for (i, entry) in resolved.inventory.entries.iter().enumerate() {
        let decision = resolved.resolutions.get(i).and_then(|r| *r);
        println!(
            "  [{i}] class={class:?} stream={stream} target={target} resolution={res:?}",
            class = entry.class,
            stream = entry.stream_identity,
            target = entry.target_identity,
            res = decision,
        );
    }
}

fn read_file_or_stdin(path: &PathBuf) -> String {
    if path.as_os_str() == "-" {
        let mut buf = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut buf) {
            eprintln!("error: failed to read stdin: {e}");
            process::exit(1);
        }
        buf
    } else {
        match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: failed to read {}: {e}", path.display());
                process::exit(1);
            }
        }
    }
}

fn parse_entry_spec(
    spec: &str,
    resolved: &ResolvedConflictInventory,
) -> Result<
    (
        usize,
        tidefs_local_filesystem::receive_merge_planner::ReceiveMergeDecision,
    ),
    String,
> {
    let (index_str, kind_str) = spec
        .split_once(':')
        .ok_or_else(|| "expected INDEX:KIND format (e.g. 0:keep_local)".to_string())?;
    let index: usize = index_str
        .parse()
        .map_err(|e| format!("invalid entry index {index_str:?}: {e}"))?;
    if index >= resolved.entry_count() {
        return Err(format!(
            "entry index {index} out of bounds (inventory has {count} entries)",
            count = resolved.entry_count()
        ));
    }
    let decision = parse_resolution_kind(kind_str).map_err(|e| e.to_string())?;
    Ok((index, decision))
}

fn parse_class_spec(
    spec: &str,
) -> Result<
    (
        tidefs_local_filesystem::encoding::ConflictClass,
        tidefs_local_filesystem::receive_merge_planner::ReceiveMergeDecision,
    ),
    String,
> {
    let (class_str, kind_str) = spec
        .split_once(':')
        .ok_or_else(|| "expected CLASS:KIND format (e.g. inode_identity:keep_local)".to_string())?;
    let class = parse_conflict_class(class_str).map_err(|e| e.to_string())?;
    let decision = parse_resolution_kind(kind_str).map_err(|e| e.to_string())?;
    Ok((class, decision))
}

fn parse_root_identity(s: &str) -> Result<ReceiveMergeRootIdentity, String> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 3 {
        return Err("expected TXG:GEN:CHECKSUM format (e.g. 42:420:0xabc)".to_string());
    }
    let txg = parse_u64_flex(parts[0]).map_err(|e| format!("invalid txg: {e}"))?;
    let gen = parse_u64_flex(parts[1]).map_err(|e| format!("invalid generation: {e}"))?;
    let checksum = parse_u64_flex(parts[2]).map_err(|e| format!("invalid checksum: {e}"))?;
    Ok(ReceiveMergeRootIdentity {
        transaction_id: txg,
        generation: gen,
        superblock_checksum: checksum,
    })
}

fn parse_u64_flex(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{e}"))
    } else if let Some(hex) = s.strip_prefix("0X") {
        u64::from_str_radix(hex, 16).map_err(|e| format!("{e}"))
    } else {
        s.parse::<u64>().map_err(|e| format!("{e}"))
    }
}
