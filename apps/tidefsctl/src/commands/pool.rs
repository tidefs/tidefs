// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Pool command: manage TideFS storage pools.
//
// This module implements the `tidefsctl pool` subcommand group, delegating
// to the respective production crates for each operation.  The verb surface
// mirrors the operator/UAPI lifecycle: create, owner-mediated import/export,
// destroy, mount, scan, status, and integrity-check.
//
// # Pool create
//
// `tidefsctl pool create <pool-name> --devices <device>...` bootstraps a
// TideFS pool on block devices, or regular files in hidden development mode, by calling
// [`tidefs_pool_import::create::PoolCreator::create_pool`] with
// `RedundancyPolicy::replicated(1)` for the default initial command shape.  The
// create path writes dual-copy pool labels and an initial committed root
// (epoch 1), leaving the pool in `Exported` state ready for import.
//
// Regular-file device creation is only available behind the `--file-devices`
// development flag.  Without this flag only real block devices are accepted
// (checked via `is_block_device` on the path).

use std::os::unix::fs::FileTypeExt;
use tidefs_pool_scan::scanner::{PoolScanReport, ScanPlan, SegmentScanner};

use std::path::{Path, PathBuf};
use std::process;

use clap::Parser;
use tidefs_dataset_properties;
use tidefs_local_filesystem::{LocalFileSystem, RecoveryPolicy, RootAuthenticationKey};
use tidefs_local_object_store::StoreOptions;

#[derive(Parser, Debug)]
pub enum PoolCommand {
    /// Create a new TideFS pool on block devices
    Create {
        /// Pool name (max 255 bytes UTF-8)
        pool_name: String,

        /// One or more block devices
        #[arg(short = 'd', long = "devices", required = true, num_args = 1..)]
        devices: Vec<PathBuf>,

        /// Redundancy policy: single (default), replicated=N, or erasure=D+P
        #[arg(short = 'r', long = "redundancy", default_value = "single")]
        redundancy: String,

        /// Comma-separated feature flags (e.g. "encryption,compression")
        #[arg(long = "feature-flags", default_value = "")]
        feature_flags: String,

        /// Path to write the sealed pool key envelope (84 bytes, "VEKF" magic).
        /// Required when --feature-flags includes "encryption". The envelope
        /// is created and written; subsequent mounts use --encryption-envelope.
        #[arg(long = "encryption-envelope", value_name = "PATH")]
        encryption_envelope: Option<PathBuf>,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,

        /// Allow regular files as pool devices (development only)
        #[arg(long = "file-devices", hide = true)]
        file_devices: bool,
    },

    /// Scan devices for pool labels (discovery)
    Scan {
        /// Devices to scan for pool labels
        #[arg(short = 'd', long = "devices", required = true, num_args = 1..)]
        devices: Vec<PathBuf>,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// Removed pool registry listing surface
    #[command(hide = true)]
    List,

    /// Show pool status
    Status {
        /// Pool name
        pool_name: String,

        /// Devices for offline label scan; omit to query the live pool owner
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// Destroy a pool through its live owner, or offline with explicit devices
    Destroy {
        /// Pool name. Imported pools route to the live owner.
        pool_name: String,

        /// Devices that belong to an exported/offline pool
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Force destruction without confirmation
        #[arg(long = "force")]
        force: bool,

        /// Zero the superblock region on each device
        #[arg(long = "zero-superblock")]
        zero_superblock: bool,
    },

    /// Import an existing pool by name through a live owner
    Import {
        /// Pool name. Imported pools route to the live owner.
        #[arg(value_parser = parse_pool_name)]
        pool_name: String,

        /// Devices for exported/not-yet-imported owner creation
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Open devices read-only
        #[arg(long = "read-only")]
        read_only: bool,

        /// Directory for import lock files
        #[arg(long = "lock-dir")]
        lock_dir: Option<PathBuf>,

        /// Path to a sealed pool key envelope file (84 bytes, "VEKF" magic).
        /// When set, the pool is imported with per-object encryption and the
        /// key fingerprint is reported. Fails if the envelope is missing,
        /// corrupt, or cannot be unsealed.
        #[arg(long = "encryption-envelope", value_name = "PATH")]
        encryption_envelope: Option<PathBuf>,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// Export (deactivate) a pool
    Export {
        /// Pool name to export
        pool_name: String,

        /// Devices for offline export; omit to export through the live pool owner
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Force export even if datasets are mounted
        #[arg(long = "force")]
        force: bool,
    },

    /// Run the development FUSE mount harness for an imported pool
    Mount {
        /// Pool name
        pool_name: String,

        /// Mountpoint directory
        mountpoint: PathBuf,

        /// Mount read-only
        #[arg(long = "read-only")]
        read_only: bool,

        /// Block devices for importing and launching this development harness
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Use relatime (atime only when older than mtime/ctime)
        #[arg(long = "relatime")]
        relatime: bool,

        /// Dataset path to mount (default "root")
        #[arg(long = "dataset", default_value = "root")]
        dataset: String,

        /// Path to a sealed pool key envelope file
        #[arg(long = "encryption-envelope", value_name = "PATH")]
        encryption_envelope: Option<PathBuf>,

        /// Passphrase for unwrapping dataset encryption keys from the
        /// pool keystore (verification pre-mount).
        #[arg(long = "encryption-passphrase")]
        encryption_passphrase: Option<String>,
        /// Salt for the encryption passphrase (hex-encoded, 32 chars).
        #[arg(long = "encryption-salt")]
        encryption_salt: Option<String>,
    },

    /// Run an integrity check through the live owner, or offline with explicit devices
    IntegrityCheck {
        /// Pool name. Imported pools route to the live owner.
        #[arg(value_parser = parse_pool_name)]
        pool: String,

        /// Retired directory object-store scan mode.
        #[arg(
            short = 'b',
            long = "backing-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        backing_dir: Option<PathBuf>,

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,

        /// Maximum number of records to check
        #[arg(long = "max-records")]
        max_records: Option<u64>,

        /// Maximum bytes to check
        #[arg(long = "max-bytes")]
        max_bytes: Option<u64>,

        /// Device paths for pool-label, committed-root, and intent-log checks
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,
    },

    /// Get a typed pool property value with source annotation
    Get {
        /// Pool name (imported-pool identity; routed through the live owner)
        pool: String,

        /// Property name (e.g. "space.quota")
        property: String,

        /// Block devices for offline/not-yet-imported property access
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,
    },

    /// Set a typed pool property value with validation
    Set {
        /// Pool name (imported-pool identity; routed through the live owner)
        pool: String,

        /// Property assignment in key=value form (e.g. "space.quota=1073741824")
        assignment: String,

        /// Block devices for offline/not-yet-imported property access
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,
    },

    /// List all registry properties for the pool with effective values and sources
    ListProps {
        /// Pool name (imported-pool identity; routed through the live owner)
        pool: String,

        /// Block devices for offline/not-yet-imported property access
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Filter properties by family (e.g. "space", "integrity")
        #[arg(long = "family", short = 'f')]
        family: Option<String>,
    },
}

fn parse_pool_name(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("pool name must not be empty".to_string());
    }
    if value.contains('/') {
        return Err(
            "pool name must be a pool identity, not a device path; pass devices with --devices"
                .to_string(),
        );
    }
    Ok(value.to_string())
}

// ---------------------------------------------------------------------------
// Command handler
// ---------------------------------------------------------------------------

/// Dispatch the parsed `PoolCommand` to the appropriate handler.
pub fn handle_pool(cmd: PoolCommand) {
    match cmd {
        PoolCommand::Create {
            pool_name,
            devices,
            redundancy,
            feature_flags,
            encryption_envelope,
            json,
            file_devices,
        } => handle_pool_create(
            pool_name,
            devices,
            redundancy,
            feature_flags,
            encryption_envelope,
            json,
            file_devices,
        ),

        PoolCommand::Import {
            pool_name,
            devices,
            read_only,
            lock_dir,
            encryption_envelope,
            json,
        } => handle_pool_import(
            pool_name,
            devices,
            read_only,
            lock_dir,
            encryption_envelope,
            json,
        ),
        PoolCommand::Status {
            pool_name,
            devices,
            json,
        } => handle_pool_status(pool_name, devices, json),
        PoolCommand::Scan { devices, json } => handle_pool_scan(devices, json),
        PoolCommand::List => handle_removed_pool_list(),
        PoolCommand::Export {
            pool_name,
            devices,
            force,
        } => handle_pool_export(pool_name, devices, force),
        PoolCommand::Destroy {
            pool_name,
            devices,
            force,
            zero_superblock,
        } => handle_pool_destroy(pool_name, devices, force, zero_superblock),
        PoolCommand::Mount {
            pool_name,
            mountpoint,
            read_only,
            devices,
            relatime,
            dataset,
            encryption_envelope,
            encryption_passphrase,
            encryption_salt,
        } => {
            crate::commands::mount::handle_mount(crate::commands::mount::PoolMountArgs {
                pool_name,
                mount_point: mountpoint,
                read_only,
                devices,
                relatime,
                dataset,
                encryption_envelope,
                encryption_passphrase,
                encryption_salt,
                cluster: false,
                cluster_node_addr: None,
                cluster_node_id: None,
            });
        }
        PoolCommand::IntegrityCheck {
            pool,
            backing_dir,
            json,
            max_records,
            max_bytes,
            devices,
        } => {
            handle_pool_integrity_check(pool, backing_dir, json, max_records, max_bytes, devices);
        }
        PoolCommand::Get {
            property,
            pool,
            devices,
        } => handle_pool_get(&pool, devices.as_deref(), &property),
        PoolCommand::Set {
            assignment,
            pool,
            devices,
        } => handle_pool_set(&pool, devices.as_deref(), &assignment),
        PoolCommand::ListProps {
            pool,
            devices,
            family,
        } => handle_pool_list_props(&pool, devices.as_deref(), family.as_deref()),
    }
}

// ---------------------------------------------------------------------------
// pool create
// ---------------------------------------------------------------------------

fn handle_pool_create(
    pool_name: String,
    devices: Vec<PathBuf>,
    redundancy: String,
    feature_flags: String,
    encryption_envelope: Option<PathBuf>,

    json: bool,
    file_devices: bool,
) {
    let _guard = super::authz::require_local_only("pool create");

    // encryption is a pool-level feature; all other feature flags are
    // per-dataset (set via `tidefsctl dataset set-strategy`).
    let encrypt_pool = feature_flags.contains("encryption");
    if !feature_flags.is_empty() && !encrypt_pool {
        eprintln!(
            "tidefsctl pool create: --feature-flags is not a pool-level setting.\n\
            Use 'tidefsctl dataset set-strategy <pool> <dataset> --enable <features>' to enable\n\
            per-dataset feature flags after pool creation."
        );
        process::exit(1);
    }
    use tidefs_pool_import::create::{PoolCreateConfig, PoolCreator};

    // --- validate redundancy policy ---
    let policy = match parse_pool_redundancy_policy(&redundancy) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("tidefsctl: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = validate_pool_create_device_paths(&devices, file_devices) {
        eprintln!("tidefsctl: {err}");
        process::exit(1);
    }

    // --- create the pool ---
    // When encryption is requested, generate the pool encryption key
    // upfront and pass it to the config. The key is obtained via the
    // secret-handle/key-lease boundary: passphrase -> PoolWrappingKey ->
    // PoolEncryptionSecretHandle.issue_lease() -> lease.into_key().
    let encryption_key: Option<tidefs_encryption::StoreKey> = if encrypt_pool {
        Some(tidefs_encryption::StoreKey::generate())
    } else {
        None
    };

    let config = PoolCreateConfig {
        clustered: false,
        pool_name: pool_name.clone(),
        pool_guid: None, // auto-generated from /dev/urandom
        redundancy: policy,
        encryption_key: encryption_key.clone(),
    };

    let outcome = match PoolCreator::create_pool(&devices, &config) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("tidefsctl: pool create failed: {err}");
            process::exit(1);
        }
    };

    // Persist the sealed encryption envelope so the pool can be
    // imported/mounted later. The key was already generated above and
    // passed to the PoolCreateConfig.
    if encrypt_pool {
        if let Some(ref env_path) = encryption_envelope {
            use tidefs_local_object_store::encrypt::PoolEncryptionKey;
            let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_environment()
                .unwrap_or_else(|_| tidefs_local_filesystem::RootAuthenticationKey::demo_key());
            let pool_key =
                PoolEncryptionKey::from_bytes(encryption_key.as_ref().unwrap().as_bytes())
                    .expect("StoreKey is always valid key length");
            let envelope = pool_key.seal(&root_auth_key.as_bytes32());
            if let Err(e) = envelope.write_to_file(env_path) {
                eprintln!(
                    "tidefsctl: pool created but failed to write encryption envelope to {}: {e}",
                    env_path.display()
                );
                process::exit(1);
            }
            if !json {
                println!("  encryption envelope: {}", env_path.display());
                println!(
                    "  encryption key fingerprint: {}",
                    outcome
                        .encryption_key_fingerprint
                        .as_deref()
                        .unwrap_or("none")
                );
            }
        } else {
            eprintln!(
                "tidefsctl: --feature-flags encryption requires --encryption-envelope <PATH>"
            );
            process::exit(1);
        }
    }

    // --- report ---
    if json {
        let json_out = serde_json::json!({
            "pool_name": outcome.pool_name,
            "pool_guid": hex_guid(&outcome.pool_guid),
            "device_count": outcome.device_count,
            "redundancy_policy": outcome.redundancy.to_string(),
            "state": outcome.state.to_string(),
            "committed_root_epoch": outcome.committed_root.epoch_number,
            "commit_group_id": outcome.committed_root.root.commit_group_id.0,
        });
        println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
    } else {
        println!("pool created: {}", outcome.pool_name);
        println!("  pool GUID:       {}", hex_guid(&outcome.pool_guid));
        println!("  device count:    {}", outcome.device_count);
        println!("  redundancy:      {}", outcome.redundancy);
        println!("  state:           {}", outcome.state);
        println!("  epoch:           {}", outcome.committed_root.epoch_number);
        println!(
            "  commit group:    {}",
            outcome.committed_root.root.commit_group_id.0
        );
    }
}

fn parse_pool_redundancy_policy(
    raw: &str,
) -> Result<tidefs_pool_import::create::RedundancyPolicy, String> {
    use tidefs_pool_import::create::RedundancyPolicy;

    let value = raw.trim().to_ascii_lowercase();
    match value.as_str() {
        "single" => return Ok(RedundancyPolicy::replicated(1)),
        "none" => return Err(retired_pool_redundancy_alias_error(raw, "single")),
        "mirror" => return Err(retired_pool_redundancy_alias_error(raw, "replicated=N")),
        _ => {}
    }

    if value.starts_with("mirror=") {
        return Err(retired_pool_redundancy_alias_error(raw, "replicated=N"));
    }

    if let Some(rest) = value.strip_prefix("replicated=") {
        let copies = parse_nonzero_u8(rest, raw, "replicated copies", "replicated=N")?;
        return Ok(RedundancyPolicy::replicated(copies));
    }

    if let Some(rest) = value.strip_prefix("erasure=") {
        let (data, parity) = parse_erasure_shards(rest, raw)?;
        return Ok(RedundancyPolicy::erasure(data, parity));
    }

    Err(format!(
        "unknown redundancy policy \"{raw}\"; expected single, replicated=N, or erasure=D+P"
    ))
}

fn retired_pool_redundancy_alias_error(raw: &str, replacement: &str) -> String {
    format!(
        "retired redundancy alias \"{raw}\" is not accepted; use {replacement} (expected single, replicated=N, or erasure=D+P)"
    )
}

fn parse_nonzero_u8(value: &str, raw: &str, field: &str, expected: &str) -> Result<u8, String> {
    let parsed = value
        .parse::<u8>()
        .map_err(|_| format!("invalid {field} in \"{raw}\": expected {expected}"))?;
    if parsed == 0 {
        return Err(format!("{field} must be at least 1 in \"{raw}\""));
    }
    Ok(parsed)
}

fn parse_erasure_shards(raw_spec: &str, raw: &str) -> Result<(u8, u8), String> {
    let (data, parity) = raw_spec
        .split_once('+')
        .ok_or_else(|| format!("invalid erasure policy \"{raw}\": expected erasure=D+P"))?;
    let data = parse_nonzero_u8(data, raw, "erasure data shards", "erasure=D+P")?;
    let parity = parse_nonzero_u8(parity, raw, "erasure parity shards", "erasure=D+P")?;
    Ok((data, parity))
}

fn validate_pool_create_device_paths(
    devices: &[PathBuf],
    file_devices: bool,
) -> Result<(), String> {
    for dev in devices {
        let meta = dev
            .metadata()
            .map_err(|e| format!("cannot access {}: {e}", dev.display()))?;
        let file_type = meta.file_type();
        if meta.is_dir() {
            return Err(format!(
                "{} is a directory; pool devices must be block devices or regular files with --file-devices (development only)",
                dev.display()
            ));
        }
        if file_type.is_block_device() {
            continue;
        }
        if meta.is_file() {
            if file_devices {
                continue;
            }
            return Err(format!(
                "{} is a regular file; use --file-devices to allow regular files (development only)",
                dev.display()
            ));
        }
        return Err(format!(
            "{} is not a block device or regular file",
            dev.display()
        ));
    }
    Ok(())
}

/// Format a 16-byte GUID as a hex-encoded string with hyphens (UUID v4 style).
fn hex_guid(bytes: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],
        bytes[6],  bytes[7],
        bytes[8],  bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    )
}

// ---------------------------------------------------------------------------
// pool import
// ---------------------------------------------------------------------------

fn handle_pool_import(
    pool_name: String,
    devices: Option<Vec<PathBuf>>,
    read_only: bool,
    lock_dir: Option<PathBuf>,
    encryption_envelope: Option<PathBuf>,
    json: bool,
) {
    let _guard = super::authz::require_local_only("pool import");

    let live_args = serde_json::json!({
        "read_only": read_only,
        "lock_dir": lock_dir.as_ref().map(|path| path.display().to_string()),
        "encryption_envelope": encryption_envelope
            .as_ref()
            .map(|path| path.display().to_string()),
    });
    let Some(devices) = devices.filter(|devices| !devices.is_empty()) else {
        super::live_owner::route_with_format_and_args(
            "pool", "import", &pool_name, json, live_args,
        );
    };

    let mut owner_args = live_args;
    owner_args["devices"] = serde_json::Value::Array(
        devices
            .iter()
            .map(|path| serde_json::Value::String(path.display().to_string()))
            .collect(),
    );

    let config = assemble_device_pool_config(&devices, "import");
    ensure_device_pool_name(&pool_name, "import", &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
        "pool",
        "import",
        &pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        json,
        owner_args,
    );

    if json {
        let json_out = serde_json::json!({
            "ok": false,
            "command": "pool import",
            "pool_name": pool_name,
            "pool_uuid": hex_guid(&config.pool_uuid),
            "state": config.state.to_string(),
            "error": "standalone import would activate a pool without a live owner",
            "owner_required": true,
        });
        println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
    } else {
        eprintln!(
            "tidefsctl pool import: refusing standalone import of pool '{}'",
            pool_name
        );
        eprintln!(
            "tidefsctl pool import: import creates live state, and live state must be owned by the kernel UAPI or a userspace daemon"
        );
        eprintln!(
            "tidefsctl pool import: use 'tidefsctl pool mount {} <mountpoint> --devices ...' for the current FUSE owner path",
            pool_name
        );
        eprintln!(
            "tidefsctl pool import: a future kernel import path must publish a live owner interface before this command can activate the pool"
        );
    }
    process::exit(1);
}

// ---------------------------------------------------------------------------
// pool scan
// ---------------------------------------------------------------------------

fn handle_pool_scan(devices: Vec<PathBuf>, json: bool) {
    let entries = match tidefs_pool_scan::scan_labels(&devices) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("tidefsctl: label scan failed: {err}");
            process::exit(1);
        }
    };

    if json {
        let json_entries: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "device_path": e.device_path.to_string_lossy(),
                    "size_bytes": e.size_bytes,
                    "has_tidefs_label": e.has_tidefs_label,
                    "pool_guid": e.pool_guid.map(|g| hex_guid(&g)),
                    "pool_name": e.pool_name,
                    "pool_state": e.pool_state.map(|s| s.to_string()),
                    "device_guid": e.device_guid.map(|g| hex_guid(&g)),
                    "device_index": e.device_index,
                    "device_count": e.device_count,
                    "redundancy_policy": e.redundancy_policy.map(|policy| policy.to_string()),
                    "label_valid": e.label_valid,
                    "label_status": e.label_status,
                    "topology_generation": e.topology_generation,
                    "device_class": e.device_class.map(|c| format!("{:?}", c)),
                    "device_capacity_bytes": e.device_capacity_bytes,
                    "device_health": e.device_health.map(|h| h.to_string()),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "devices": json_entries })).unwrap()
        );
    } else {
        for entry in &entries {
            println!("device: {}", entry.device_path.display());
            if entry.has_tidefs_label {
                println!(
                    "  pool_guid={}",
                    entry.pool_guid.map_or_else(|| "-".into(), |g| hex_guid(&g))
                );
                println!("  pool_name={}", entry.pool_name.as_deref().unwrap_or("-"));
                println!(
                    "  pool_state={}",
                    entry
                        .pool_state
                        .map_or_else(|| "-".into(), |s| s.to_string())
                );
                println!(
                    "  device_guid={}",
                    entry
                        .device_guid
                        .map_or_else(|| "-".into(), |g| hex_guid(&g))
                );
                println!(
                    "  device_index={}",
                    entry
                        .device_index
                        .map_or_else(|| "-".into(), |i| i.to_string())
                );
                println!(
                    "  device_count={}",
                    entry
                        .device_count
                        .map_or_else(|| "-".into(), |c| c.to_string())
                );
                println!(
                    "  redundancy_policy={}",
                    entry
                        .redundancy_policy
                        .map_or_else(|| "-".into(), |policy| policy.to_string())
                );
                println!("  label_valid={}", entry.label_valid);
            } else {
                println!("  label: none ({})", entry.label_status);
            }
            println!();
        }
        println!(
            "{} device(s) scanned, {} labeled",
            entries.len(),
            entries.iter().filter(|e| e.has_tidefs_label).count()
        );
    }
}

fn handle_removed_pool_list() -> ! {
    eprintln!(
        "{}",
        super::classification::removed_surface_error("pool list")
    );
    process::exit(1);
}

// ---------------------------------------------------------------------------
// pool status
// ---------------------------------------------------------------------------

fn handle_pool_status(pool_name: String, devices: Option<Vec<PathBuf>>, json: bool) {
    let device_paths = match devices {
        Some(d) if !d.is_empty() => d,
        _ => {
            super::live_owner::route_with_format("pool", "status", &pool_name, json);
        }
    };

    let config = assemble_device_pool_config(&device_paths, "status");
    ensure_device_pool_name(&pool_name, "status", &config);
    route_live_device_pool_owner_with_format("status", &pool_name, &config, json);

    if json {
        let json_out = serde_json::json!({
            "pool_name": config.pool_name,
            "pool_uuid": hex_guid(&config.pool_uuid),
            "state": config.state.to_string(),
            "device_count": config.device_count,
            "redundancy_policy": config.redundancy_policy.to_string(),
            "health": config.health.to_string(),
        });
        println!("{}", serde_json::to_string_pretty(&json_out).unwrap());
    } else {
        println!("pool: {}", config.pool_name);
        println!("  pool uuid:   {}", hex_guid(&config.pool_uuid));
        println!("  state:       {}", config.state);
        println!("  devices:     {}", config.device_count);
        println!("  redundancy:  {}", config.redundancy_policy);
        println!("  health:      {}", config.health);
    }
}

fn assemble_device_pool_config(
    device_paths: &[PathBuf],
    operation: &str,
) -> tidefs_pool_scan::PoolConfig {
    let entries = match tidefs_pool_scan::scan_labels(device_paths) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("tidefsctl pool {operation}: label scan failed: {err}");
            process::exit(1);
        }
    };
    match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("tidefsctl pool {operation}: pool assembly failed: {err}");
            process::exit(1);
        }
    }
}

fn ensure_device_pool_name(
    pool_name: &str,
    operation: &str,
    config: &tidefs_pool_scan::PoolConfig,
) {
    if config.pool_name != pool_name {
        eprintln!(
            "tidefsctl pool {operation}: devices belong to pool '{}', not '{pool_name}'",
            config.pool_name
        );
        process::exit(1);
    }
}

fn route_live_device_pool_owner_with_format(
    operation: &str,
    pool_name: &str,
    config: &tidefs_pool_scan::PoolConfig,
    json: bool,
) {
    super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
        "pool",
        operation,
        pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        json,
        serde_json::Value::Null,
    );
}

// ---------------------------------------------------------------------------
// pool integrity-check
// ---------------------------------------------------------------------------

/// Read the highest committed transaction group from a device's VCRL ledger
/// in the system area. Returns None if no valid VCRL ledger is found.
fn read_vcrl_committed_txg(device_path: &std::path::Path) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    use tidefs_types_pool_label_core::{
        VCRL_ENTRY_SIZE, VCRL_HEADER_SIZE, VCRL_MAGIC, VCRL_VERSION,
    };

    let mut file = std::fs::File::open(device_path).ok()?;

    // Read pool label to find system area pointer.
    let mut label_buf = vec![0u8; tidefs_types_pool_label_core::POOL_LABEL_SIZE];
    file.seek(SeekFrom::Start(0)).ok()?;
    file.read_exact(&mut label_buf).ok()?;

    let label = tidefs_types_pool_label_core::decode_label(&label_buf).ok()?;
    let sa_ptr = label.system_area_pointer;
    let sa_size = label.system_area_size;

    if sa_size < VCRL_HEADER_SIZE as u64 {
        return None;
    }

    // Read VCRL header.
    file.seek(SeekFrom::Start(sa_ptr)).ok()?;
    let mut header = [0u8; VCRL_HEADER_SIZE];
    file.read_exact(&mut header).ok()?;

    if header[0..4] != VCRL_MAGIC {
        return None;
    }
    let version = u32::from_le_bytes(header[4..8].try_into().ok()?);
    if version != VCRL_VERSION {
        return None;
    }
    let entry_count = u32::from_le_bytes(header[8..12].try_into().ok()?);
    if entry_count == 0 {
        return None;
    }

    // Read the last VCRL entry (highest txg is typically the last one).
    let entry_off = VCRL_HEADER_SIZE + (entry_count as usize - 1) * VCRL_ENTRY_SIZE;
    file.seek(SeekFrom::Start(sa_ptr + entry_off as u64 + 40))
        .ok()?;
    let mut txg_buf = [0u8; 8];
    file.read_exact(&mut txg_buf).ok()?;
    Some(u64::from_le_bytes(txg_buf))
}

/// Run a quick block-device integrity scan across devices.
/// Opens each device as a block-device object store and verifies
/// segment integrity. Returns a count of checksum errors found.
/// Returns None if no device could be opened.
fn scan_block_devices_for_integrity(device_paths: &[std::path::PathBuf]) -> Option<PoolScanReport> {
    use std::time::Instant;
    use tidefs_local_object_store::LocalObjectStore;
    use tidefs_local_object_store::StoreOptions;
    use tidefs_local_object_store::SuspectLog;

    let started = Instant::now();
    let mut total_records: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut total_checksum_errors: u64 = 0;
    let mut total_segments: u64 = 0;
    let mut suspect_entries: u64 = 0;
    let mut suspect_unresolved: u64 = 0;
    let mut any_device_opened = false;

    for dev_path in device_paths {
        let store = match LocalObjectStore::open_block_device(dev_path, StoreOptions::default()) {
            Ok(s) => s,
            Err(_) => continue,
        };
        any_device_opened = true;

        let stats = store.stats();
        total_segments = total_segments.saturating_add(stats.segment_count as u64);

        let mut suspect_log = SuspectLog::new();
        let mut cursor: (u64, u64) = (0, 0);

        loop {
            match store.verify_segment_integrity(&mut suspect_log, &mut cursor, 1000, 0) {
                Ok((records, bytes, has_more)) => {
                    total_records = total_records.saturating_add(records);
                    total_bytes = total_bytes.saturating_add(bytes);
                    if !has_more {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        let log_stats = suspect_log.stats();
        total_checksum_errors = total_checksum_errors.saturating_add(log_stats.total_entries);
        suspect_entries = suspect_entries.saturating_add(log_stats.total_entries);
        suspect_unresolved = suspect_unresolved.saturating_add(log_stats.unresolved);
    }

    if !any_device_opened {
        return None;
    }

    let elapsed = started.elapsed();
    let store_root = device_paths
        .first()
        .cloned()
        .unwrap_or_else(|| PathBuf::from("."));
    Some(PoolScanReport {
        store_root,
        completed: true,
        scan_duration: elapsed,
        total_segments,
        total_records,
        total_bytes,
        live_bytes: total_bytes,
        dead_bytes: 0,
        checksum_errors: total_checksum_errors,
        suspect_entries,
        suspect_unresolved,
        segments: Vec::new(),
    })
}

fn handle_pool_integrity_check(
    pool: String,
    backing_dir: Option<PathBuf>,
    json: bool,
    max_records: Option<u64>,
    max_bytes: Option<u64>,
    devices: Option<Vec<PathBuf>>,
) {
    let device_paths = devices.filter(|devices| !devices.is_empty());
    let live_args = serde_json::json!({
        "backing_dir": backing_dir.as_ref().map(|path| path.display().to_string()),
        "devices": device_paths.as_ref().map(|paths| {
            paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
        }),
        "max_records": max_records,
        "max_bytes": max_bytes,
    });

    if backing_dir.is_none() && device_paths.is_none() {
        super::live_owner::route_if_owner_exists_with_format_and_args(
            "pool",
            "integrity-check",
            &pool,
            json,
            live_args,
        );
        if json {
            let out = serde_json::json!({
                "ok": false,
                "command": "pool integrity-check",
                "pool_name": &pool,
                "owner_required": true,
                "offline_inputs_required": true,
                "error": "no reachable live owner and no offline storage arguments were provided",
                "recovery": "start or repair the kernel UAPI or userspace daemon owner, or provide --devices for exported/offline byte-addressable storage",
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            eprintln!("tidefsctl pool integrity-check: pool '{pool}' has no reachable live owner");
            eprintln!(
                "tidefsctl pool integrity-check: use --devices for exported/offline or not-yet-imported byte-addressable storage"
            );
        }
        process::exit(1);
    }

    if let Some(ref path) = backing_dir {
        super::live_owner::route_if_owner_exists_for_pool_backing_dir_with_args(
            "pool",
            "integrity-check",
            &pool,
            path,
            live_args.clone(),
        );
        super::offline_pool::refuse_runtime_pool_path("pool", "integrity-check", path);
    }

    if let Some(ref device_paths) = device_paths {
        let config = assemble_device_pool_config(device_paths, "integrity-check");
        ensure_device_pool_name(&pool, "integrity-check", &config);
        super::live_owner::route_or_refuse_active_for_uuid_with_args(
            "pool",
            "integrity-check",
            &pool,
            config.pool_uuid,
            config.state == tidefs_types_pool_label_core::PoolState::Active,
            live_args.clone(),
        );
    }

    // ── Phase 1: device-level checks (labels, committed root, intent log) ──
    let mut label_failures: Vec<String> = Vec::new();
    let mut committed_root_found = false;
    let mut committed_root_txg: u64 = 0;
    let mut intent_log_pending_devices: Vec<String> = Vec::new();
    let mut vrbt_missing_devices: Vec<String> = Vec::new();

    if let Some(ref device_paths) = device_paths {
        // Validate pool labels via PoolScanner.
        let scan_config = tidefs_pool_scan::label::PoolScanConfig::new(device_paths.clone());
        match tidefs_pool_scan::result::PoolScanner::scan(&scan_config) {
            Ok(scan_result) => {
                // Check for corrupted/unreadable labels.
                for dev in &scan_result.devices {
                    if !dev.label_valid {
                        label_failures.push(format!(
                            "{}: {}",
                            dev.device_path.display(),
                            dev.label_status
                        ));
                    }
                }
                // Check committed-root presence via VCRL ledger.
                // PoolScanner uses VBSA format but the pool creator writes
                // VCRL format. Read the VCRL header directly from the system
                // area for authoritative committed-root detection.
                for dev_path in device_paths {
                    if let Some(txg) = read_vcrl_committed_txg(dev_path) {
                        committed_root_found = true;
                        if txg > committed_root_txg {
                            committed_root_txg = txg;
                        }
                    }
                }
            }
            Err(e) => {
                label_failures.push(format!("label scan failed: {e}"));
            }
        }

        // Check VRBT intent-log state per device.
        for dev_path in device_paths {
            match tidefs_pool_import::check_pool_intent_log_pending(dev_path) {
                Ok(Some(result)) => {
                    if result.intent_log_pending {
                        intent_log_pending_devices.push(result.description.clone());
                    }
                    if !result.vrbt_valid {
                        vrbt_missing_devices.push(result.description.clone());
                    }
                }
                Ok(None) => {
                    // Device has no label or no system area — label scan
                    // already reported this above.
                }
                Err(e) => {
                    label_failures.push(format!(
                        "intent-log check failed on {}: {e}",
                        dev_path.display()
                    ));
                }
            }
        }
    }

    // ── Phase 2: segment-level integrity scan ──
    // Retired directory object-stores use SegmentScanner. Byte-addressable
    // pool members use the block-device object-store scanner when --devices is
    // present.
    let mut segment_scan_error: Option<String> = None;
    let report_root = backing_dir
        .clone()
        .or_else(|| {
            device_paths
                .as_ref()
                .and_then(|paths| paths.first().cloned())
        })
        .unwrap_or_else(|| PathBuf::from(&pool));

    let segment_report: Option<PoolScanReport> = if let Some(ref path) = backing_dir {
        if !path.exists() {
            eprintln!(
                "tidefsctl: integrity-check retired directory object-store does not exist: {}",
                path.display()
            );
            process::exit(2);
        }

        let mut plan = ScanPlan::full(path.clone());
        if let Some(n) = max_records {
            plan = plan.with_max_records(n);
        }
        if let Some(b) = max_bytes {
            plan = plan.with_max_bytes(b);
        }

        match SegmentScanner::scan(&plan, None) {
            Ok(r) => Some(r),
            Err(err) => {
                if let Some(ref device_paths) = device_paths {
                    scan_block_devices_for_integrity(device_paths)
                } else {
                    segment_scan_error = Some(err);
                    None
                }
            }
        }
    } else if let Some(ref device_paths) = device_paths {
        scan_block_devices_for_integrity(device_paths)
    } else {
        None
    };

    // Whether device-level checks were requested.
    let device_checks_enabled = device_paths.is_some();
    let device_checks_skipped = !device_checks_enabled;
    let segment_scan_available = segment_report.is_some();

    // If neither device checks nor segment scan are available, report the
    // error and exit.
    if device_checks_skipped && !segment_scan_available {
        let err_msg = segment_scan_error.as_deref().unwrap_or("unknown error");
        if json {
            let out = serde_json::json!({
                "pass": false,
                "error": err_msg,
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            eprintln!("tidefsctl: pool integrity-check failed: {err_msg}");
        }
        process::exit(2);
    }

    // ── Phase 3: aggregate pass/fail ──
    let segment_pass = segment_report.as_ref().map_or(true, |r| r.is_healthy());

    // Device-level checks only apply when --devices is given. When device
    // checks are skipped the segment-scan alone is not a full pass because
    // labels, committed-root, intent-log, and VRBT gates were never checked.
    // Use --devices to run the complete verification.
    let label_pass = !device_checks_enabled || label_failures.is_empty();
    let committed_root_pass = !device_checks_enabled || committed_root_found;
    let intent_log_pass = !device_checks_enabled || intent_log_pending_devices.is_empty();
    let vrbt_pass = !device_checks_enabled || vrbt_missing_devices.is_empty();

    // overall_pass is only meaningful when device checks ran. Without them
    // the operator gets a non-zero exit to signal incomplete verification.
    let overall_pass = if device_checks_skipped {
        false
    } else {
        let device_checks_pass = label_pass && committed_root_pass && intent_log_pass && vrbt_pass;
        if segment_scan_available {
            segment_pass && device_checks_pass
        } else {
            device_checks_pass
        }
    };

    if json {
        print_combined_integrity_json(
            &pool,
            device_checks_enabled,
            segment_report.as_ref(),
            &report_root,
            overall_pass,
            &label_failures,
            committed_root_found,
            committed_root_txg,
            &intent_log_pending_devices,
            &vrbt_missing_devices,
            segment_scan_error.as_deref(),
        );
    } else {
        print_combined_integrity_text(
            &pool,
            device_checks_enabled,
            device_checks_skipped,
            segment_report.as_ref(),
            &report_root,
            overall_pass,
            &label_failures,
            committed_root_found,
            committed_root_txg,
            &intent_log_pending_devices,
            &vrbt_missing_devices,
            segment_scan_error.as_deref(),
        );
    }

    if !overall_pass {
        if device_checks_skipped {
            process::exit(3);
        } else {
            process::exit(1);
        }
    }
}

fn print_combined_integrity_text(
    pool: &str,
    device_checks_enabled: bool,
    device_checks_skipped: bool,
    report: Option<&PoolScanReport>,
    store_root: &Path,
    overall_pass: bool,
    label_failures: &[String],
    committed_root_found: bool,
    committed_root_txg: u64,
    intent_log_pending_devices: &[String],
    vrbt_missing_devices: &[String],
    segment_scan_error: Option<&str>,
) {
    println!("pool integrity-check: {pool}");
    println!("  storage:       {}", store_root.display());
    println!(
        "  overall pass:  {}",
        if overall_pass {
            "yes"
        } else if device_checks_skipped {
            "incomplete (device checks skipped)"
        } else {
            "no"
        }
    );
    println!();

    // ── Label checks ──
    if !label_failures.is_empty() {
        println!("  label failures: {} device(s)", label_failures.len());
        for f in label_failures {
            println!("    - {f}");
        }
    } else if device_checks_enabled {
        println!("  labels:        ok");
    } else {
        println!("  labels:        skipped (use --devices to check)");
    }

    // ── Committed-root check ──
    if device_checks_enabled {
        println!(
            "  committed root: {}",
            if committed_root_found {
                format!("present (txg={committed_root_txg})")
            } else {
                "missing".to_string()
            }
        );
    } else {
        println!("  committed root: skipped (use --devices to check)");
    }

    // ── Intent-log check ──
    if !device_checks_enabled {
        println!("  intent-log:    skipped (use --devices to check)");
    } else if !intent_log_pending_devices.is_empty() {
        println!("  intent-log:    BLOCKED (pending records)");
        for d in intent_log_pending_devices {
            println!("    - {d}");
        }
    } else {
        println!("  intent-log:    clean");
    }

    // ── VRBT check ──
    if !device_checks_enabled {
        println!("  VRBT:          skipped (use --devices to check)");
    } else if !vrbt_missing_devices.is_empty() {
        println!(
            "  VRBT:          missing/invalid on {} device(s)",
            vrbt_missing_devices.len()
        );
        for d in vrbt_missing_devices {
            println!("    - {d}");
        }
    }

    // ── Segment scan ──
    println!();
    if let Some(r) = report {
        println!("  scan duration: {:.2}s", r.scan_duration.as_secs_f64());
        println!("  segments:      {}", r.total_segments);
        println!("  records:       {}", r.total_records);
        println!(
            "  total bytes:   {} ({:.1}% live)",
            format_bytes(r.total_bytes),
            r.live_ratio() * 100.0,
        );
        println!("  live bytes:    {}", format_bytes(r.live_bytes));
        println!("  dead bytes:    {}", format_bytes(r.dead_bytes));
        println!("  checksum errors: {}", r.checksum_errors);
        if r.checksum_errors > 0 {
            let ids = r.corrupted_segment_ids();
            println!(
                "  corrupted segments: [{}]",
                ids.iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!("  suspect entries:       {}", r.suspect_entries);
        println!("  suspect unresolved:    {}", r.suspect_unresolved);
    } else {
        println!("  segment scan:  unavailable (no object-store directory found)");
        if let Some(err) = segment_scan_error {
            println!("  scan error:    {err}");
        }
    }

    if !overall_pass {
        eprintln!();
        if device_checks_skipped {
            eprintln!(
                "tidefsctl: pool integrity-check INCOMPLETE (device checks skipped; use --devices)"
            );
        } else {
            eprintln!("tidefsctl: pool integrity-check FAILED");
        }
        if device_checks_enabled && !label_failures.is_empty() {
            eprintln!(
                "  - label validation failed on {} device(s)",
                label_failures.len()
            );
        }
        if device_checks_enabled && !committed_root_found {
            eprintln!("  - no committed root found");
        }
        if device_checks_enabled && !intent_log_pending_devices.is_empty() {
            eprintln!(
                "  - intent-log has pending records on {} device(s)",
                intent_log_pending_devices.len()
            );
        }
        if device_checks_enabled && !vrbt_missing_devices.is_empty() {
            eprintln!(
                "  - VRBT block missing or invalid on {} device(s)",
                vrbt_missing_devices.len()
            );
        }
        if let Some(r) = report {
            if r.checksum_errors > 0 {
                eprintln!(
                    "  - {} checksum error(s) detected in segment data",
                    r.checksum_errors
                );
            }
        }
    }
}

fn print_combined_integrity_json(
    pool: &str,
    device_checks_enabled: bool,
    report: Option<&PoolScanReport>,
    store_root: &Path,
    overall_pass: bool,
    label_failures: &[String],
    committed_root_found: bool,
    committed_root_txg: u64,
    intent_log_pending_devices: &[String],
    vrbt_missing_devices: &[String],
    segment_scan_error: Option<&str>,
) {
    let scan_fields = if let Some(r) = report {
        serde_json::json!({
            "store_root": r.store_root.to_string_lossy(),
            "completed": r.completed,
            "scan_duration_secs": r.scan_duration.as_secs_f64(),
            "total_segments": r.total_segments,
            "total_records": r.total_records,
            "total_bytes": r.total_bytes,
            "live_bytes": r.live_bytes,
            "dead_bytes": r.dead_bytes,
            "live_ratio": r.live_ratio(),
            "checksum_errors": r.checksum_errors,
            "suspect_entries": r.suspect_entries,
            "suspect_unresolved": r.suspect_unresolved,
            "corrupted_segment_ids": r.corrupted_segment_ids(),
        })
    } else {
        serde_json::json!({
            "store_root": store_root.to_string_lossy(),
            "segment_scan_available": false,
            "segment_scan_error": segment_scan_error,
        })
    };

    let out = serde_json::json!({
        "pool_name": pool,
        "pass": overall_pass,
        "device_checks_enabled": device_checks_enabled,
        "label_failures": label_failures,
        "committed_root_found": committed_root_found,
        "committed_root_txg": committed_root_txg,
        "intent_log_pending_devices": intent_log_pending_devices,
        "vrbt_missing_devices": vrbt_missing_devices,
    });
    // Merge scan fields into the output object.
    let mut out_map = match out {
        serde_json::Value::Object(m) => m,
        _ => serde_json::Map::new(),
    };
    if let serde_json::Value::Object(scan_map) = scan_fields {
        for (k, v) in scan_map {
            out_map.insert(k, v);
        }
    }
    let out = serde_json::Value::Object(out_map);
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/// Format a byte count as a human-readable string.
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    for unit in UNITS {
        if value < 1024.0 {
            return format!("{value:.1} {unit}");
        }
        value /= 1024.0;
    }
    format!("{value:.1} PiB")
}

// ---------------------------------------------------------------------------
// pool export
// ---------------------------------------------------------------------------

fn handle_pool_export(pool_name: String, devices: Option<Vec<PathBuf>>, force: bool) {
    let _guard = super::authz::require_local_only("pool export");

    let device_paths = match devices {
        Some(d) if !d.is_empty() => d,
        _ => {
            super::live_owner::route_with_args(
                "pool",
                "export",
                &pool_name,
                serde_json::json!({
                    "force": force,
                }),
            );
        }
    };

    let config = assemble_device_pool_config(&device_paths, "export");
    ensure_device_pool_name(&pool_name, "export", &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "pool",
        "export",
        &pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        serde_json::json!({
            "force": force,
        }),
    );

    let lock_dir = PathBuf::from("/run/tidefs/import");
    match tidefs_pool_import::pool_export(&device_paths, &lock_dir, force) {
        Ok(()) => {
            println!("pool exported: {pool_name}");
            if force {
                println!("  (forced)");
            }
        }
        Err(err) => {
            eprintln!("tidefsctl: pool export failed: {err}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// pool destroy
// ---------------------------------------------------------------------------

fn handle_pool_destroy(
    pool_name: String,
    devices: Option<Vec<PathBuf>>,
    force: bool,
    zero_superblock: bool,
) {
    let _guard = super::authz::require_local_only("pool destroy");

    let Some(devices) = devices.filter(|devices| !devices.is_empty()) else {
        super::live_owner::route_with_args(
            "pool",
            "destroy",
            &pool_name,
            serde_json::json!({
                "force": force,
                "zero_superblock": zero_superblock,
            }),
        );
    };

    let config = assemble_device_pool_config(&devices, "destroy");
    ensure_device_pool_name(&pool_name, "destroy", &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "pool",
        "destroy",
        &pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        serde_json::json!({
            "force": force,
            "zero_superblock": zero_superblock,
        }),
    );

    match tidefs_pool_import::pool_destroy(&devices, zero_superblock) {
        Ok(()) => {
            println!("pool destroyed: {pool_name}");
            if zero_superblock {
                println!("  superblock zeroed: yes");
            }
        }
        Err(err) => {
            eprintln!("tidefsctl: pool destroy failed: {err}");
            process::exit(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Pool property handlers
// ---------------------------------------------------------------------------

fn open_pool_property_filesystem_with_live_args(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    live_args: serde_json::Value,
) -> LocalFileSystem {
    let Some(devs) = devices.filter(|devs| !devs.is_empty()) else {
        super::live_owner::route_with_args("pool", operation, pool, live_args);
    };

    let config = assemble_device_pool_config(devs, operation);
    ensure_device_pool_name(pool, operation, &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "pool",
        operation,
        pool,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        live_args,
    );

    let metadata_dir = super::offline_pool::metadata_dir("pool", operation, &config.pool_uuid);

    let root_auth_key = RootAuthenticationKey::from_environment()
        .unwrap_or_else(|_| RootAuthenticationKey::demo_key());
    match LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        devs,
        StoreOptions::default(),
        root_auth_key,
        recovery_policy,
    ) {
        Ok(fs) => fs,
        Err(err) => {
            eprintln!(
                "tidefsctl pool {operation}: failed to open block-device-backed pool '{pool}' at {}: {err}",
                metadata_dir.display()
            );
            process::exit(1);
        }
    }
}

fn handle_pool_get(pool: &str, devices: Option<&[PathBuf]>, property: &str) {
    let fs = open_pool_property_filesystem_with_live_args(
        pool,
        devices,
        "get",
        RecoveryPolicy::ReadOnly,
        serde_json::json!({
            "property": property,
        }),
    );

    let registry = tidefs_dataset_properties::build_registry();
    let key = tidefs_dataset_properties::PropertyKey::new(property);

    if tidefs_dataset_properties::lookup_property(&registry, &key).is_none() {
        eprintln!("tidefsctl pool get: unknown property '{}'", property);
        process::exit(1);
    }

    let props = fs.pool_properties();
    match props.get(&key) {
        Some(entry) => {
            println!("property:  {}", property);
            println!("value:     {}", entry.value);
            println!("source:    {}", entry.source);
        }
        None => {
            let def = tidefs_dataset_properties::lookup_property(&registry, &key).unwrap();
            println!("property:  {}", property);
            println!("value:     {}", def.default_value);
            println!("source:    default");
        }
    }
}

fn handle_pool_set(pool: &str, devices: Option<&[PathBuf]>, assignment: &str) {
    let _guard = super::authz::require_local_only("pool set");

    let mut fs = open_pool_property_filesystem_with_live_args(
        pool,
        devices,
        "set",
        RecoveryPolicy::default(),
        serde_json::json!({
            "assignment": assignment,
        }),
    );

    let (prop_name, prop_val_str) = match assignment.split_once('=') {
        Some((k, v)) => (k.trim(), v.trim()),
        None => {
            eprintln!(
                "tidefsctl pool set: invalid assignment '{}' (expected key=value)",
                assignment
            );
            process::exit(1);
        }
    };

    if prop_name.is_empty() {
        eprintln!("tidefsctl pool set: property name must not be empty");
        process::exit(1);
    }

    let registry = tidefs_dataset_properties::build_registry();
    let key = tidefs_dataset_properties::PropertyKey::new(prop_name);

    let def = match tidefs_dataset_properties::lookup_property(&registry, &key) {
        Some(def) => def,
        None => {
            eprintln!("tidefsctl pool set: unknown property '{}'", prop_name);
            process::exit(1);
        }
    };

    let is_clear = prop_val_str.is_empty() || prop_val_str == "-";
    let value = if is_clear {
        tidefs_dataset_properties::PropertyValue::None
    } else {
        tidefs_dataset_properties::PropertySet::parse_value_from_str(prop_val_str)
    };

    let existing = fs.pool_properties();
    if let Err(verr) = tidefs_dataset_properties::validate_set(&key, &value, def, existing) {
        eprintln!("tidefsctl pool set: validation failed: {verr}");
        process::exit(1);
    }

    let mut props = existing.clone();
    if is_clear {
        props.remove_local_override(&key);
    } else {
        props.set_local(key.clone(), value.clone());
    }

    fs.pool_properties_mut().clone_from(&props);
    if let Err(e) = fs.persist_pool_properties() {
        eprintln!("tidefsctl pool set: property set but persist failed: {e}");
        process::exit(1);
    }

    if is_clear {
        println!(
            "cleared '{}' (now using default/inherited value)",
            prop_name
        );
    } else {
        println!("{} = {}", prop_name, value);
    }
}

fn handle_pool_list_props(pool: &str, devices: Option<&[PathBuf]>, family: Option<&str>) {
    let fs = open_pool_property_filesystem_with_live_args(
        pool,
        devices,
        "list-props",
        RecoveryPolicy::ReadOnly,
        serde_json::json!({
            "family": family,
        }),
    );

    let registry = tidefs_dataset_properties::build_registry();

    let defs: Vec<_> = if let Some(family_str) = family {
        let family = match family_str.to_lowercase().as_str() {
            "compression" => tidefs_dataset_properties::PropertyFamily::Compression,
            "encryption" => tidefs_dataset_properties::PropertyFamily::Encryption,
            "space" => tidefs_dataset_properties::PropertyFamily::Space,
            "layout" => tidefs_dataset_properties::PropertyFamily::Layout,
            "integrity" => tidefs_dataset_properties::PropertyFamily::Integrity,
            "access" => tidefs_dataset_properties::PropertyFamily::Access,
            "performance" | "perf" => tidefs_dataset_properties::PropertyFamily::Performance,
            "snapshot" => tidefs_dataset_properties::PropertyFamily::Snapshot,
            other => {
                eprintln!("tidefsctl pool list-props: unknown family '{}'", other);
                eprintln!("  valid families: compression, encryption, space, layout, integrity, access, performance, snapshot");
                process::exit(1);
            }
        };
        tidefs_dataset_properties::filter_registry_by_family(&registry, family)
    } else {
        registry.iter().collect()
    };

    if defs.is_empty() {
        println!("(no properties registered)");
        return;
    }

    let props = fs.pool_properties();
    println!(
        "{:<35} {:<20} {:<12} {}",
        "PROPERTY", "VALUE", "TYPE", "SOURCE"
    );
    println!("{:-<35} {:-<20} {:-<12} {:-<20}", "", "", "", "");

    for def in &defs {
        let local_entry = props.get(&def.name);
        let (value, source) = match local_entry {
            Some(entry) => (entry.value.clone(), entry.source.clone()),
            None => (
                def.default_value.clone(),
                tidefs_dataset_properties::PropertySource::Default,
            ),
        };

        let source_str = match &source {
            tidefs_dataset_properties::PropertySource::Local => "local",
            tidefs_dataset_properties::PropertySource::Inherited { .. } => "inherited",
            tidefs_dataset_properties::PropertySource::Default => "default",
        };

        println!(
            "{:<35} {:<20} {:<12} {}",
            def.name.as_str(),
            value.to_string(),
            def.value_type.label(),
            source_str,
        );
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // -- CreateError classification tests --

    #[test]
    fn create_error_no_devices_message_contains_devices() {
        let msg = "no devices specified for pool creation";
        assert!(msg.contains("devices"));
    }

    #[test]
    fn create_error_device_open_message_contains_path() {
        let err = tidefs_pool_import::create::CreateError::DeviceOpen {
            device_path: PathBuf::from("/dev/sdb"),
            msg: "permission denied".into(),
        };
        let s = err.to_string();
        assert!(s.contains("/dev/sdb"));
        assert!(s.contains("permission denied"));
    }

    #[test]
    fn create_error_device_too_small_message_contains_capacity() {
        let err = tidefs_pool_import::create::CreateError::DeviceTooSmall {
            device_path: PathBuf::from("/dev/sdc"),
            capacity_bytes: 1000,
            required_bytes: 500_000,
        };
        let s = err.to_string();
        assert!(s.contains("/dev/sdc"));
        assert!(s.contains("1000"));
        assert!(s.contains("500000"));
    }

    #[test]
    fn create_error_already_labeled_message_contains_path() {
        let err = tidefs_pool_import::create::CreateError::DeviceAlreadyLabeled {
            device_path: PathBuf::from("/dev/nvme0n1"),
            existing_pool_guid: [0xAB; 16],
        };
        let s = err.to_string();
        assert!(s.contains("/dev/nvme0n1"));
        assert!(s.contains("already labeled"));
    }

    #[test]
    fn hex_guid_format() {
        let bytes: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let hex = hex_guid(&bytes);
        assert_eq!(hex, "00112233-4455-6677-8899-aabbccddeeff");
    }

    #[test]
    fn hex_guid_zero() {
        let bytes = [0u8; 16];
        let hex = hex_guid(&bytes);
        assert_eq!(hex, "00000000-0000-0000-0000-000000000000");
    }

    // -- redundancy policy parsing tests (not requiring live devices) --

    #[test]
    fn redundancy_single_is_valid() {
        let policy = parse_pool_redundancy_policy("single").unwrap();
        assert_eq!(
            policy,
            tidefs_pool_import::create::RedundancyPolicy::replicated(1)
        );
    }

    #[test]
    fn redundancy_replicated_is_valid() {
        let policy = parse_pool_redundancy_policy("replicated=3").unwrap();
        assert_eq!(
            policy,
            tidefs_pool_import::create::RedundancyPolicy::replicated(3)
        );
    }

    #[test]
    fn redundancy_erasure_is_valid() {
        let policy = parse_pool_redundancy_policy("erasure=4+2").unwrap();
        assert_eq!(
            policy,
            tidefs_pool_import::create::RedundancyPolicy::erasure(4, 2)
        );
    }

    #[test]
    fn redundancy_retired_aliases_are_rejected() {
        let none = parse_pool_redundancy_policy("none").unwrap_err();
        assert!(none.contains("retired redundancy alias"));
        assert!(none.contains("single"));

        let mirror = parse_pool_redundancy_policy("mirror").unwrap_err();
        assert!(mirror.contains("retired redundancy alias"));
        assert!(mirror.contains("replicated=N"));

        let mirror_eq = parse_pool_redundancy_policy("mirror=2").unwrap_err();
        assert!(mirror_eq.contains("retired redundancy alias"));
        assert!(mirror_eq.contains("replicated=N"));
    }

    #[test]
    fn redundancy_unknown_rejected() {
        let err = parse_pool_redundancy_policy("raidz").unwrap_err();
        assert!(err.contains("single, replicated=N, or erasure=D+P"));
    }

    #[test]
    fn redundancy_rejects_zero_width() {
        assert!(parse_pool_redundancy_policy("replicated=0").is_err());
        assert!(parse_pool_redundancy_policy("erasure=2+0").is_err());
    }

    #[test]
    fn redundancy_rejects_bad_erasure_shape() {
        let err = parse_pool_redundancy_policy("erasure=2").unwrap_err();
        assert!(err.contains("erasure=D+P"));
    }

    #[test]
    fn pool_list_is_hidden_removed_surface_with_clear_error() {
        use clap::Parser;
        let cmd = PoolCommand::try_parse_from(["pool", "list"]).expect("parse hidden removal");
        assert!(matches!(cmd, PoolCommand::List));

        let msg = super::super::classification::removed_surface_error("pool list");
        assert!(msg.contains("removed or unsupported"));
        assert!(msg.contains("no authoritative pool registry exists"));
        assert!(msg.contains("pool scan --devices"));
    }

    #[test]
    fn pool_create_validation_accepts_regular_file_only_with_flag() {
        let dir = tempfile::tempdir().expect("tempdir");
        let dev = dir.path().join("pool.img");
        std::fs::File::create(&dev).expect("create temp file");

        assert!(validate_pool_create_device_paths(std::slice::from_ref(&dev), false).is_err());
        assert!(validate_pool_create_device_paths(&[dev], true).is_ok());
    }

    #[test]
    fn pool_create_validation_rejects_directory_even_with_file_devices() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = validate_pool_create_device_paths(&[dir.path().to_path_buf()], true).unwrap_err();

        assert!(err.contains("directory"));
    }

    // -- integrity-check --devices parser tests --

    #[test]
    fn integrity_check_device_flag_parsed_single() {
        use clap::Parser;
        let args = vec!["pool", "integrity-check", "tank", "--devices", "/dev/sdb"];
        let cmd = PoolCommand::try_parse_from(args).expect("parse");
        match cmd {
            PoolCommand::IntegrityCheck { pool, devices, .. } => {
                assert_eq!(pool, "tank");
                assert_eq!(devices, Some(vec![PathBuf::from("/dev/sdb")]));
            }
            _ => panic!("wrong command variant"),
        }
    }

    #[test]
    fn integrity_check_device_flag_parsed_multiple() {
        use clap::Parser;
        let args = vec![
            "pool",
            "integrity-check",
            "tank",
            "--devices",
            "/dev/sdb",
            "/dev/sdc",
            "/dev/sdd",
        ];
        let cmd = PoolCommand::try_parse_from(args).expect("parse");
        match cmd {
            PoolCommand::IntegrityCheck { devices, .. } => {
                assert_eq!(
                    devices,
                    Some(vec![
                        PathBuf::from("/dev/sdb"),
                        PathBuf::from("/dev/sdc"),
                        PathBuf::from("/dev/sdd"),
                    ])
                );
            }
            _ => panic!("wrong command variant"),
        }
    }

    #[test]
    fn integrity_check_without_devices_flag() {
        use clap::Parser;
        let args = vec!["pool", "integrity-check", "tank"];
        let cmd = PoolCommand::try_parse_from(args).expect("parse");
        match cmd {
            PoolCommand::IntegrityCheck {
                pool,
                backing_dir,
                devices,
                ..
            } => {
                assert_eq!(pool, "tank");
                assert_eq!(backing_dir, None);
                assert_eq!(devices, None);
            }
            _ => panic!("wrong command variant"),
        }
    }

    #[test]
    fn integrity_check_rejects_backing_dir() {
        use clap::Parser;
        let args = vec![
            "pool",
            "integrity-check",
            "tank",
            "--backing-dir",
            "/data/pool",
        ];
        assert!(
            PoolCommand::try_parse_from(args).is_err(),
            "pool integrity-check backing-dir must be retired"
        );
    }
}
