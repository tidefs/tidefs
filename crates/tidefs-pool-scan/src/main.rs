//! CLI entry point for `tidefs-pool-scan`.
//!
//! Usage:
//!   tidefs-pool-scan scan                    # scan all block devices
//!   tidefs-pool-scan scan --devices /dev/sda,/dev/sdb
//!   tidefs-pool-scan scan --include-virtual   # include loop/ram devices
//!   tidefs-pool-scan scan --json              # JSON output
//!   tidefs-pool-scan assemble                 # assemble from scan report
//!   tidefs-pool-scan assemble --pool-uuid <hex>
//!   tidefs-pool-scan assemble --json

use std::path::PathBuf;
use std::process;

use tidefs_pool_scan::{scan_devices, PoolAssembler};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("usage: tidefs-pool-scan <scan|assemble> [flags]");
        process::exit(1);
    }

    match args[1].as_str() {
        "scan" => cmd_scan(&args),
        "assemble" => cmd_assemble(&args),
        other => {
            eprintln!("unknown command: {other}");
            eprintln!("usage: tidefs-pool-scan <scan|assemble> [flags]");
            process::exit(1);
        }
    }
}

fn cmd_scan(args: &[String]) {
    let mut device_paths: Vec<PathBuf> = Vec::new();
    let mut include_virtual = false;
    let mut json_output = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--devices" => {
                i += 1;
                if i < args.len() {
                    device_paths = args[i]
                        .split(',')
                        .map(|s| PathBuf::from(s.trim()))
                        .filter(|p| p.exists())
                        .collect();
                }
            }
            "--include-virtual" => {
                include_virtual = true;
            }
            "--json" => {
                json_output = true;
            }
            other => {
                eprintln!("unknown flag: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    let report = match scan_devices(&device_paths, include_virtual) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e}");
            process::exit(1);
        }
    };

    if json_output {
        match serde_json::to_string_pretty(&report) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("json serialization failed: {e}");
                process::exit(1);
            }
        }
    } else {
        report.print_summary();
    }
}

fn cmd_assemble(args: &[String]) {
    let mut pool_uuid: Option<[u8; 16]> = None;
    let mut json_output = false;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--pool-uuid" => {
                i += 1;
                if i < args.len() {
                    let hex = args[i].trim();
                    if hex.len() != 32 {
                        eprintln!("--pool-uuid requires 32 hex characters (16 bytes)");
                        process::exit(1);
                    }
                    let mut uuid = [0u8; 16];
                    for (j, chunk) in hex.as_bytes().chunks(2).enumerate() {
                        if j >= 16 {
                            break;
                        }
                        let byte_str = std::str::from_utf8(chunk).unwrap_or("00");
                        uuid[j] = u8::from_str_radix(byte_str, 16).unwrap_or(0);
                    }
                    pool_uuid = Some(uuid);
                }
            }
            "--json" => {
                json_output = true;
            }
            other => {
                eprintln!("unknown flag: {other}");
                process::exit(1);
            }
        }
        i += 1;
    }

    // For the assemble command, we first scan all devices, then
    // assemble from the scan results.
    let report = match scan_devices(&[], false) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("scan failed: {e}");
            process::exit(1);
        }
    };

    let entries: Vec<_> = report.devices.values().cloned().collect();
    let config = match PoolAssembler::assemble(&entries, pool_uuid) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("assembly failed: {e}");
            process::exit(1);
        }
    };

    if json_output {
        match serde_json::to_string_pretty(&config) {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("json serialization failed: {e}");
                process::exit(1);
            }
        }
    } else {
        println!("=== Pool Configuration ===");
        println!("Pool name:    {}", config.pool_name);
        println!("Pool UUID:    {:02x?}", config.pool_uuid);
        println!("State:        {}", config.state);
        println!("Health:       {}", config.health);
        println!("Topology gen: {}", config.topology_generation);
        println!(
            "Devices:      {}/{} ({} missing)",
            config
                .device_count
                .saturating_sub(config.missing_indices.len() as u32),
            config.device_count,
            config.missing_indices.len(),
        );
        if !config.missing_indices.is_empty() {
            println!("Missing:      {:?}", config.missing_indices);
        }
        println!(
            "Capacity:     {} MiB",
            config.total_capacity_bytes / (1024 * 1024)
        );
        println!(
            "Importable:   {}",
            if config.is_importable() { "yes" } else { "no" }
        );
    }
}
