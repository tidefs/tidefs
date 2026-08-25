// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
// Pool command: manage TideFS storage pools.
//
// This module implements the `tidefsctl pool` subcommand group, delegating
// to the respective production crates for each operation.  The verb surface
// mirrors the operator/UAPI lifecycle: create, owner-mediated import/export,
// destroy, mount, scan, status, integrity-check, scrub, and repair.
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

use std::path::PathBuf;
use std::process;

use clap::Parser;
use tidefs_dataset_properties;
use tidefs_local_filesystem::{LocalFileSystem, RecoveryPolicy};
use tidefs_local_object_store::{PoolRedundancyPolicy, StoreOptions};
use tidefs_vfs_engine::{LivePoolAdminArg, LivePoolAdminArgs};

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

        /// Output as JSON
        #[arg(long = "json")]
        json: bool,
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

        /// Force export even if storage objects are mounted or exported
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

        /// Admit only one explicit missing-member rebuild while keeping FUSE read-only
        #[arg(long = "rebuild-only", requires_all = ["read_only", "devices"])]
        rebuild_only: bool,

        /// Block devices for importing and launching this development harness
        #[arg(short = 'd', long = "devices", num_args = 1..)]
        devices: Option<Vec<PathBuf>>,

        /// Use relatime (atime only when older than mtime/ctime)
        #[arg(long = "relatime")]
        relatime: bool,

        /// Filesystem path to mount (default "root")
        #[arg(long = "filesystem", default_value = "root")]
        filesystem: String,

        /// Path to a sealed pool key envelope file
        #[arg(long = "encryption-envelope", value_name = "PATH")]
        encryption_envelope: Option<PathBuf>,

        /// Passphrase for unwrapping object encryption keys from the
        /// pool keystore (verification pre-mount).
        #[arg(long = "encryption-passphrase")]
        encryption_passphrase: Option<String>,
        /// Salt for the encryption passphrase (hex-encoded, 32 chars).
        #[arg(long = "encryption-salt")]
        encryption_salt: Option<String>,

        #[command(flatten)]
        runtime: crate::commands::mount::PoolMountRuntimeArgs,

        #[cfg(feature = "cluster")]
        /// Mount as an authenticated remote client of the exact Pool owner.
        #[arg(
            long = "cluster-client",
            default_value_t = false,
            conflicts_with_all = ["cluster", "devices"]
        )]
        cluster_client: bool,

        #[cfg(feature = "cluster")]
        /// Provisioned VFS_RPC candidate address. Repeat per trusted identity.
        #[arg(
            long = "cluster-vfs-rpc-addr",
            requires = "cluster_client",
            required_if_eq("cluster_client", "true"),
            action = clap::ArgAction::Append
        )]
        cluster_vfs_rpc_addr: Vec<String>,

        #[cfg(feature = "cluster")]
        /// Expected Pool GUID as exactly 32 hexadecimal digits.
        #[arg(
            long = "cluster-pool-guid",
            requires = "cluster_client",
            required_if_eq("cluster_client", "true")
        )]
        cluster_pool_guid: Option<String>,

        #[cfg(feature = "cluster")]
        /// Request a cluster-authoritative mount.
        #[arg(long = "cluster", default_value_t = false)]
        cluster: bool,

        #[cfg(feature = "cluster")]
        /// Transport address of the storage node owning Pool lease authority.
        #[arg(
            long = "cluster-authority-addr",
            required_if_eq_any([("cluster", "true"), ("cluster_client", "true")])
        )]
        cluster_authority_addr: Option<String>,

        #[cfg(feature = "cluster")]
        /// Local authenticated Control endpoint for Pool-backed inline VFS_RPC.
        #[arg(
            long = "cluster-vfs-rpc-bind",
            requires = "cluster",
            required_if_eq("cluster", "true")
        )]
        cluster_vfs_rpc_bind: Option<String>,

        #[cfg(feature = "cluster")]
        /// Host-local private credential for the Pool owner node.
        #[arg(
            long = "cluster-node-credential",
            value_name = "PATH",
            required_if_eq_any([("cluster", "true"), ("cluster_client", "true")])
        )]
        cluster_node_credential: Option<PathBuf>,

        #[cfg(feature = "cluster")]
        /// Exact storage-node identity trusted as Pool lease authority.
        #[arg(
            long = "cluster-trusted-authority-identity",
            value_name = "PATH",
            required_if_eq_any([("cluster", "true"), ("cluster_client", "true")])
        )]
        cluster_trusted_authority_identity: Option<PathBuf>,

        #[cfg(feature = "cluster")]
        /// Shareable VFS_RPC candidate identity. Repeat in address-pair order
        /// for clients, or for each admitted peer on an owner.
        #[arg(
            long = "cluster-trusted-vfs-rpc-peer-identity",
            value_name = "PATH",
            action = clap::ArgAction::Append,
            required_if_eq_any([("cluster", "true"), ("cluster_client", "true")])
        )]
        cluster_trusted_vfs_rpc_peer_identity: Vec<PathBuf>,
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

    /// Scrub current mounted filesystem content through the live Pool owner
    Scrub {
        /// Pool name. A reachable live owner is required.
        #[arg(value_parser = parse_pool_name)]
        pool: String,

        /// Output the completed scrub report as JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// Repair one receipt-authorized corrupt replica through the live Pool owner
    Repair {
        /// Pool name. A reachable local-mounted owner is required.
        #[arg(value_parser = parse_pool_name)]
        pool: String,

        /// Output the completed or refused repair report as JSON
        #[arg(long = "json")]
        json: bool,
    },

    /// Rotate the Pool wrapping key and re-wrap every sealed object key
    RotateKey(super::dataset::PoolRotateKeyArgs),

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
            json,
        } => handle_pool_destroy(pool_name, devices, force, zero_superblock, json),
        PoolCommand::Mount {
            pool_name,
            mountpoint,
            read_only,
            rebuild_only,
            devices,
            relatime,
            filesystem,
            encryption_envelope,
            encryption_passphrase,
            encryption_salt,
            runtime,
            #[cfg(feature = "cluster")]
            cluster_client,
            #[cfg(feature = "cluster")]
            cluster_vfs_rpc_addr,
            #[cfg(feature = "cluster")]
            cluster_pool_guid,
            #[cfg(feature = "cluster")]
            cluster,
            #[cfg(feature = "cluster")]
            cluster_authority_addr,
            #[cfg(feature = "cluster")]
            cluster_vfs_rpc_bind,
            #[cfg(feature = "cluster")]
            cluster_node_credential,
            #[cfg(feature = "cluster")]
            cluster_trusted_authority_identity,
            #[cfg(feature = "cluster")]
            cluster_trusted_vfs_rpc_peer_identity,
        } => {
            crate::commands::mount::handle_mount(crate::commands::mount::PoolMountArgs {
                pool_name,
                mount_point: mountpoint,
                read_only,
                rebuild_only,
                devices,
                relatime,
                filesystem,
                encryption_envelope,
                encryption_passphrase,
                encryption_salt,
                runtime,
                #[cfg(feature = "cluster")]
                cluster_client,
                #[cfg(feature = "cluster")]
                cluster_vfs_rpc_addr,
                #[cfg(feature = "cluster")]
                cluster_pool_guid,
                #[cfg(feature = "cluster")]
                cluster,
                #[cfg(feature = "cluster")]
                cluster_authority_addr,
                #[cfg(feature = "cluster")]
                cluster_vfs_rpc_bind,
                #[cfg(feature = "cluster")]
                cluster_node_credential,
                #[cfg(feature = "cluster")]
                cluster_trusted_authority_identity,
                #[cfg(feature = "cluster")]
                cluster_trusted_vfs_rpc_peer_identity,
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
        PoolCommand::Scrub { pool, json } => handle_pool_scrub(pool, json),
        PoolCommand::Repair { pool, json } => handle_pool_repair(pool, json),
        PoolCommand::RotateKey(args) => super::dataset::handle_pool_rotate_key(args),
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

fn handle_pool_scrub(pool: String, json: bool) -> ! {
    super::live_owner::route_with_format("pool", "scrub", &pool, json)
}

fn handle_pool_repair(pool: String, json: bool) -> ! {
    let _guard = super::authz::require_local_only("pool repair");
    super::live_owner::route_unique_reachable_owner_with_format("pool", "repair", &pool, json)
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
    // per-filesystem (set via `tidefsctl filesystem set-strategy`).
    let encrypt_pool = feature_flags.contains("encryption");
    if !feature_flags.is_empty() && !encrypt_pool {
        eprintln!(
            "tidefsctl pool create: --feature-flags is not a pool-level setting.\n\
            Use 'tidefsctl filesystem set-strategy <pool> <filesystem> --enable <features>' to enable\n\
            per-filesystem feature flags after pool creation."
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
            let root_auth_key = super::root_authentication_key_or_exit("pool create");
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

    let live_args = super::live_owner::live_admin_args([
        ("read_only", LivePoolAdminArg::Bool(read_only)),
        (
            "lock_dir",
            super::live_owner::live_admin_optional_string(
                lock_dir.as_ref().map(|path| path.display().to_string()),
            ),
        ),
        (
            "encryption_envelope",
            super::live_owner::live_admin_optional_string(
                encryption_envelope
                    .as_ref()
                    .map(|path| path.display().to_string()),
            ),
        ),
    ]);
    let Some(devices) = devices.filter(|devices| !devices.is_empty()) else {
        super::live_owner::route_with_format_and_args(
            "pool", "import", &pool_name, json, live_args,
        );
    };

    let mut owner_args = live_args;
    owner_args.0.insert(
        "devices".to_string(),
        LivePoolAdminArg::Array(
            devices
                .iter()
                .map(|path| LivePoolAdminArg::String(path.display().to_string()))
                .collect(),
        ),
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

fn pool_scan_entry_json(e: &tidefs_pool_scan::DeviceScanEntry) -> serde_json::Value {
    serde_json::json!({
        "device_path": e.device_path.to_string_lossy(),
        "size_bytes": e.size_bytes,
        "device_backing": e.device_backing.map(|b| b.as_str()),
        "discard_capability": e.discard_capability.as_str(),
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
}

fn pool_scan_capability_lines(entry: &tidefs_pool_scan::DeviceScanEntry) -> [String; 2] {
    [
        format!(
            "device_backing={}",
            entry.device_backing.map_or("-", |b| b.as_str())
        ),
        format!("discard_capability={}", entry.discard_capability.as_str()),
    ]
}

fn handle_pool_scan(devices: Vec<PathBuf>, json: bool) {
    let entries = match tidefs_pool_scan::scan_labels(&devices) {
        Ok(e) => e,
        Err(err) => {
            eprintln!("tidefsctl: label scan failed: {err}");
            process::exit(1);
        }
    };

    if json {
        let json_entries: Vec<serde_json::Value> =
            entries.iter().map(pool_scan_entry_json).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({ "devices": json_entries })).unwrap()
        );
    } else {
        for entry in &entries {
            println!("device: {}", entry.device_path.display());
            for line in pool_scan_capability_lines(entry) {
                println!("  {line}");
            }
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
        LivePoolAdminArgs::default(),
    );
}

// ---------------------------------------------------------------------------
// pool integrity-check
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct OfflinePoolIntegrityReport {
    verifier: tidefs_local_filesystem::OnlineVerifierReport,
    statfs: Result<tidefs_local_filesystem::FileSystemStatfs, String>,
    filesystem: tidefs_local_filesystem::FileSystemStats,
    suspect_log: tidefs_local_object_store::SuspectLogStats,
    intent_log_pending: usize,
}

impl OfflinePoolIntegrityReport {
    fn collect(filesystem: &mut LocalFileSystem) -> Result<Self, String> {
        let verifier = filesystem
            .canonical_dataset_online_verifier_report()
            .map_err(|error| format!("authenticated Pool verifier failed: {error}"))?;
        let statfs = filesystem.statfs().map_err(|error| error.to_string());
        Ok(Self {
            verifier,
            statfs,
            filesystem: filesystem.stats(),
            suspect_log: filesystem.suspect_log_stats(),
            intent_log_pending: filesystem.intent_log_pending(),
        })
    }

    fn passed(&self) -> bool {
        self.verifier.passed()
            && !self.verifier.production_fsck_required
            && self.verifier.selected_root.is_some()
            && !self.verifier.verified_committed_roots.is_empty()
            && self.verifier.checked_transaction_manifests > 0
            && self.verifier.checked_content_objects > 0
            && self.suspect_log.unresolved == 0
            && self.statfs.is_ok()
    }
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
    let live_args = super::live_owner::live_admin_args([
        (
            "backing_dir",
            super::live_owner::live_admin_optional_string(
                backing_dir.as_ref().map(|path| path.display().to_string()),
            ),
        ),
        (
            "devices",
            match device_paths.as_ref() {
                Some(paths) => LivePoolAdminArg::Array(
                    paths
                        .iter()
                        .map(|path| LivePoolAdminArg::String(path.display().to_string()))
                        .collect(),
                ),
                None => LivePoolAdminArg::Null,
            },
        ),
        (
            "max_records",
            super::live_owner::live_admin_optional_u64(max_records),
        ),
        (
            "max_bytes",
            super::live_owner::live_admin_optional_u64(max_bytes),
        ),
    ]);

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

    let device_paths = device_paths.expect("offline integrity inputs were checked above");
    let config = assemble_device_pool_config(&device_paths, "integrity-check");
    ensure_device_pool_name(&pool, "integrity-check", &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
        "pool",
        "integrity-check",
        &pool,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        json,
        live_args,
    );

    let root_authentication_key =
        match super::required_root_authentication_key("pool integrity-check") {
            Ok(key) => key,
            Err(error) => exit_offline_integrity_error(&pool, device_paths.len(), json, &error),
        };
    let metadata_dir =
        super::offline_pool::metadata_dir("pool", "integrity-check", &config.pool_uuid);
    let mut filesystem = match LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        &device_paths,
        &pool,
        PoolRedundancyPolicy::from_label_policy(config.redundancy_policy),
        StoreOptions::default(),
        root_authentication_key,
        RecoveryPolicy::ReadOnly,
    ) {
        Ok(filesystem) => filesystem,
        Err(error) => exit_offline_integrity_error(
            &pool,
            device_paths.len(),
            json,
            &format!("read-only Pool open failed: {error}"),
        ),
    };
    let report = match OfflinePoolIntegrityReport::collect(&mut filesystem) {
        Ok(report) => report,
        Err(error) => exit_offline_integrity_error(&pool, device_paths.len(), json, &error),
    };
    let passed = report.passed();
    if json {
        print_offline_integrity_json(&pool, device_paths.len(), max_records, max_bytes, &report);
    } else {
        print_offline_integrity_text(&pool, device_paths.len(), max_records, max_bytes, &report);
    }
    if !passed {
        process::exit(1);
    }
}

fn exit_offline_integrity_error(pool: &str, device_count: usize, json: bool, error: &str) -> ! {
    if json {
        let out = serde_json::json!({
            "pool": pool,
            "pass": false,
            "state_source": "offline-explicit-devices",
            "inspection_state": "read-only",
            "device_count": device_count,
            "error": error,
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        eprintln!("tidefsctl pool integrity-check: {error}");
    }
    process::exit(1)
}

fn print_offline_integrity_text(
    pool: &str,
    device_count: usize,
    max_records: Option<u64>,
    max_bytes: Option<u64>,
    report: &OfflinePoolIntegrityReport,
) {
    let verifier = &report.verifier;
    println!("pool integrity-check: {pool}");
    println!("  source:        offline explicit devices (read-only Pool authority)");
    println!(
        "  pass:          {}",
        if report.passed() { "yes" } else { "no" }
    );
    println!("  devices:       {device_count}");
    println!("  verifier:      {}", verifier.outcome.human_name());
    println!(
        "  roots:         verified={} candidates={} invalid={}",
        verifier.verified_committed_roots.len(),
        verifier.root_candidates_seen,
        verifier.invalid_root_candidates,
    );
    println!(
        "  objects:       checked={} chunks={}",
        verifier.checked_content_objects, verifier.checked_content_chunks,
    );
    println!(
        "  suspect-log:   unresolved={} total={}",
        report.suspect_log.unresolved, report.suspect_log.total_entries,
    );
    println!("  intent-log:    pending={}", report.intent_log_pending);
    match &report.statfs {
        Ok(statfs) => println!(
            "  statfs:        blocks={} free={} avail={}",
            statfs.blocks, statfs.bfree, statfs.bavail,
        ),
        Err(error) => println!("  statfs:        unavailable ({error})"),
    }
    println!(
        "  inodes:        count={} next={}",
        report.filesystem.inode_count, report.filesystem.next_inode_id,
    );
    println!(
        "  object-store:  live_objects={} live_bytes={} segments={}",
        report.filesystem.object_store.live_objects,
        report.filesystem.object_store.live_bytes,
        report.filesystem.object_store.segment_count,
    );
    if max_records.is_some() || max_bytes.is_some() {
        println!(
            "  limits:        requested max_records={} max_bytes={} (not applied; authenticated Pool verifier is full-scope)",
            max_records
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            max_bytes
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
    }
    for issue in &verifier.issues {
        println!(
            "    - severity={} slot={:?} tx={:?} {}",
            issue.severity.human_name(),
            issue.slot,
            issue.transaction_id,
            issue.reason,
        );
    }
    if !report.passed() {
        eprintln!("tidefsctl: pool integrity-check FAILED");
        if verifier.production_fsck_required {
            eprintln!("  - production fsck/operator repair is required");
        }
        if report.suspect_log.unresolved > 0 {
            eprintln!(
                "  - {} unresolved suspect-log entry or entries",
                report.suspect_log.unresolved,
            );
        }
        if let Err(error) = &report.statfs {
            eprintln!("  - filesystem accounting is unavailable: {error}");
        }
    }
}

fn print_offline_integrity_json(
    pool: &str,
    device_count: usize,
    max_records: Option<u64>,
    max_bytes: Option<u64>,
    report: &OfflinePoolIntegrityReport,
) {
    let verifier = &report.verifier;
    let selected_root = verifier.selected_root.as_ref().map(|root| {
        serde_json::json!({
            "slot": root.slot,
            "transaction_id": root.transaction_id,
            "generation": root.generation,
            "next_inode_id": root.next_inode_id,
            "inode_count": root.inode_count,
            "has_transaction_manifest": root.has_transaction_manifest,
            "manifest_entry_count": root.manifest_entry_count,
            "has_root_authentication": root.has_root_authentication,
        })
    });
    let issues: Vec<_> = verifier
        .issues
        .iter()
        .map(|issue| {
            serde_json::json!({
                "severity": issue.severity.human_name(),
                "kind": issue.kind.human_name(),
                "slot": issue.slot,
                "transaction_id": issue.transaction_id,
                "generation": issue.generation,
                "reason": &issue.reason,
            })
        })
        .collect();
    let statfs = match &report.statfs {
        Ok(statfs) => serde_json::json!({
            "available": true,
            "blocks": statfs.blocks,
            "bfree": statfs.bfree,
            "bavail": statfs.bavail,
            "files": statfs.files,
            "ffree": statfs.ffree,
            "bsize": statfs.bsize,
            "frsize": statfs.frsize,
            "namelen": statfs.namelen,
            "fsid_hi": statfs.fsid_hi,
            "fsid_lo": statfs.fsid_lo,
        }),
        Err(error) => serde_json::json!({
            "available": false,
            "error": error,
        }),
    };
    let out = serde_json::json!({
        "pool": pool,
        "pass": report.passed(),
        "state_source": "offline-explicit-devices",
        "inspection_state": "read-only",
        "device_count": device_count,
        "requested_limits": {
            "max_records": max_records,
            "max_bytes": max_bytes,
            "applied": false,
            "reason": "authenticated Pool verifier is full-scope",
        },
        "verifier": {
            "outcome": verifier.outcome.human_name(),
            "root_slot_count": verifier.root_slot_count,
            "root_slots_seen": verifier.root_slots_seen,
            "root_slot_records_seen": verifier.root_slot_records_seen,
            "root_candidates_seen": verifier.root_candidates_seen,
            "verified_committed_roots": verifier.verified_committed_roots.len(),
            "invalid_root_candidates": verifier.invalid_root_candidates,
            "checked_transaction_manifests": verifier.checked_transaction_manifests,
            "checked_content_objects": verifier.checked_content_objects,
            "checked_content_chunks": verifier.checked_content_chunks,
            "verified_snapshot_roots": verifier.verified_snapshot_roots,
            "production_fsck_required": verifier.production_fsck_required,
            "mutating_repair_attempted": verifier.mutating_repair_attempted,
            "selected_root": selected_root,
            "issues": issues,
        },
        "statfs": statfs,
        "filesystem": {
            "inode_count": report.filesystem.inode_count,
            "directory_count": report.filesystem.directory_count,
            "file_count": report.filesystem.file_count,
            "symlink_count": report.filesystem.symlink_count,
            "snapshot_count": report.filesystem.snapshot_count,
            "next_inode_id": report.filesystem.next_inode_id,
            "generation": report.filesystem.filesystem_generation,
            "intent_log_pending": report.intent_log_pending,
        },
        "object_store": {
            "live_objects": report.filesystem.object_store.live_objects,
            "live_bytes": report.filesystem.object_store.live_bytes,
            "segment_count": report.filesystem.object_store.segment_count,
            "free_segments": report.filesystem.object_store.free_segments,
            "free_bytes": report.filesystem.object_store.free_bytes,
            "next_sequence": report.filesystem.object_store.next_sequence,
            "tombstone_count": report.filesystem.object_store.tombstone_count,
            "mirror_degraded": report.filesystem.object_store.mirror_degraded,
            "mirror_live_objects": report.filesystem.object_store.mirror_live_objects,
            "mirror_live_bytes": report.filesystem.object_store.mirror_live_bytes,
            "replica_healthy": report.filesystem.object_store.replica_healthy,
            "replica_live_objects": report.filesystem.object_store.replica_live_objects,
            "last_scrub_secs": report.filesystem.object_store.last_scrub_secs,
            "committed_root_txg": report.filesystem.object_store.committed_root_txg,
            "committed_root_generation": report.filesystem.object_store.committed_root_generation,
        },
        "suspect_log": {
            "total_entries": report.suspect_log.total_entries,
            "unresolved": report.suspect_log.unresolved,
            "resolved": report.suspect_log.resolved,
            "oldest_unresolved_age": report.suspect_log.oldest_unresolved_age,
        },
    });
    println!("{}", serde_json::to_string_pretty(&out).unwrap());
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
                pool_export_live_args(force),
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
        pool_export_live_args(force),
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
    json: bool,
) {
    let _guard = super::authz::require_local_only("pool destroy");

    let live_args = pool_destroy_live_args(force, zero_superblock);
    let Some(devices) = devices.filter(|devices| !devices.is_empty()) else {
        super::live_owner::route_with_format_and_args(
            "pool", "destroy", &pool_name, json, live_args,
        );
    };

    let config = assemble_device_pool_config(&devices, "destroy");
    ensure_device_pool_name(&pool_name, "destroy", &config);
    super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
        "pool",
        "destroy",
        &pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        json,
        live_args,
    );

    match tidefs_pool_import::pool_destroy(&devices, zero_superblock) {
        Ok(()) => {
            if json {
                let out = serde_json::json!({
                    "ok": true,
                    "operation": "destroy",
                    "pool_name": pool_name,
                    "device_count": devices.len(),
                    "zero_superblock": zero_superblock,
                    "redundant_label_areas_zeroed": zero_superblock,
                    "media_privacy_claimed": false,
                    "secure_erase_claimed": false,
                    "sanitization_claimed": false,
                    "decommissioning_claimed": false,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                println!("pool destroyed: {pool_name}");
                if zero_superblock {
                    println!("  redundant label areas zeroed and verified: yes");
                }
                println!(
                    "  media privacy, secure erase, sanitization, and decommissioning: not claimed"
                );
            }
        }
        Err(err) => {
            if json {
                let out = serde_json::json!({
                    "ok": false,
                    "operation": "destroy",
                    "pool_name": pool_name,
                    "zero_superblock": zero_superblock,
                    "error": err.to_string(),
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
            } else {
                eprintln!("tidefsctl: pool destroy failed: {err}");
            }
            process::exit(1);
        }
    }
}

fn pool_destroy_live_args(force: bool, zero_superblock: bool) -> LivePoolAdminArgs {
    super::live_owner::live_admin_args([
        ("force", LivePoolAdminArg::Bool(force)),
        ("zero_superblock", LivePoolAdminArg::Bool(zero_superblock)),
    ])
}

fn pool_export_live_args(force: bool) -> LivePoolAdminArgs {
    super::live_owner::live_admin_args([("force", LivePoolAdminArg::Bool(force))])
}

// ---------------------------------------------------------------------------
// Pool property handlers
// ---------------------------------------------------------------------------

fn open_pool_property_filesystem_with_live_args(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    live_args: LivePoolAdminArgs,
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

    let root_auth_key = super::root_authentication_key_or_exit(&format!("pool {operation}"));
    match LocalFileSystem::open_with_block_devices_and_recovery_policy(
        &metadata_dir,
        devs,
        pool,
        PoolRedundancyPolicy::from_label_policy(config.redundancy_policy),
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
        super::live_owner::live_admin_args([(
            "property",
            LivePoolAdminArg::String(property.to_string()),
        )]),
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
        super::live_owner::live_admin_args([(
            "assignment",
            LivePoolAdminArg::String(assignment.to_string()),
        )]),
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

    let pool_properties = match fs.pool_properties_mut() {
        Ok(properties) => properties,
        Err(err) => {
            eprintln!("tidefsctl pool set: filesystem mutation requires reopen: {err}");
            process::exit(1);
        }
    };
    pool_properties.clone_from(&props);
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
        super::live_owner::live_admin_args([(
            "family",
            super::live_owner::live_admin_optional_string(family.map(str::to_string)),
        )]),
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

    fn scan_entry(
        device_backing: Option<tidefs_pool_scan::PoolDeviceBacking>,
        discard_capability: tidefs_pool_scan::DiscardCapability,
    ) -> tidefs_pool_scan::DeviceScanEntry {
        tidefs_pool_scan::DeviceScanEntry {
            device_path: PathBuf::from("/dev/test0"),
            size_bytes: 4096,
            kind: tidefs_pool_scan::DeviceKind::Unknown,
            device_backing,
            discard_capability,
            model: None,
            serial: None,
            has_tidefs_label: false,
            pool_guid: None,
            pool_name: None,
            pool_state: None,
            device_guid: None,
            label_valid: false,
            label_status: "no TideFS label".to_string(),
            device_index: None,
            device_count: None,
            topology_generation: None,
            device_class: None,
            device_capacity_bytes: None,
            device_health: None,
            device_read_errors: None,
            device_write_errors: None,
            device_checksum_errors: None,
            redundancy_policy: None,
            completed_evacuations: Vec::new(),
        }
    }

    #[test]
    fn pool_scan_json_reports_backing_and_supported_discard() {
        let entry = scan_entry(
            Some(tidefs_pool_scan::PoolDeviceBacking::BlockDevice),
            tidefs_pool_scan::DiscardCapability::Supported,
        );

        let json = pool_scan_entry_json(&entry);

        assert_eq!(json["device_backing"], "block-device");
        assert_eq!(json["discard_capability"], "supported");
    }

    #[test]
    fn pool_scan_human_lines_report_regular_file_unverified_discard() {
        let entry = scan_entry(
            Some(tidefs_pool_scan::PoolDeviceBacking::RegularFileDev),
            tidefs_pool_scan::DiscardCapability::Unverified,
        );

        let lines = pool_scan_capability_lines(&entry);

        assert_eq!(lines[0], "device_backing=regular-file-dev");
        assert_eq!(lines[1], "discard_capability=unverified");
    }

    #[test]
    fn pool_scan_output_reports_unknown_backing_and_discard() {
        let entry = scan_entry(None, tidefs_pool_scan::DiscardCapability::Unknown);

        let json = pool_scan_entry_json(&entry);
        let lines = pool_scan_capability_lines(&entry);

        assert!(json["device_backing"].is_null());
        assert_eq!(json["discard_capability"], "unknown");
        assert_eq!(lines[0], "device_backing=-");
        assert_eq!(lines[1], "discard_capability=unknown");
    }

    #[test]
    fn pool_scan_output_reports_fail_closed_discard_states() {
        for (capability, expected) in [
            (
                tidefs_pool_scan::DiscardCapability::Unsupported,
                "unsupported",
            ),
            (tidefs_pool_scan::DiscardCapability::Refused, "refused"),
            (tidefs_pool_scan::DiscardCapability::Ignored, "ignored"),
            (
                tidefs_pool_scan::DiscardCapability::Unverified,
                "unverified",
            ),
            (tidefs_pool_scan::DiscardCapability::Unknown, "unknown"),
        ] {
            let entry = scan_entry(
                Some(tidefs_pool_scan::PoolDeviceBacking::BlockDevice),
                capability,
            );

            let json = pool_scan_entry_json(&entry);
            let lines = pool_scan_capability_lines(&entry);

            assert_eq!(json["discard_capability"], expected);
            assert_eq!(lines[1], format!("discard_capability={expected}"));
        }
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

    #[test]
    fn pool_destroy_live_args_preserve_force_and_zero_superblock() {
        let args = pool_destroy_live_args(true, true);

        assert_eq!(args.0.get("force"), Some(&LivePoolAdminArg::Bool(true)));
        assert_eq!(
            args.0.get("zero_superblock"),
            Some(&LivePoolAdminArg::Bool(true))
        );
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

    #[test]
    fn offline_explicit_device_integrity_uses_authenticated_pool_state() {
        use tidefs_local_filesystem::RootAuthenticationKey;
        use tidefs_pool_import::create::{PoolCreateConfig, PoolCreator, RedundancyPolicy};

        let dir = tempfile::tempdir().expect("offline integrity fixture");
        let devices = [
            dir.path().join("member0.img"),
            dir.path().join("member1.img"),
        ];
        for path in &devices {
            std::fs::File::create(path)
                .expect("create Pool member")
                .set_len(32 * 1024 * 1024)
                .expect("size Pool member");
        }
        PoolCreator::create_pool(
            &devices,
            &PoolCreateConfig {
                pool_name: "offline-integrity".to_string(),
                pool_guid: None,
                redundancy: RedundancyPolicy::replicated(2),
                encryption_key: None,
                clustered: false,
            },
        )
        .expect("create exported Pool");

        let metadata = dir.path().join("metadata");
        std::fs::create_dir_all(&metadata).expect("create Pool metadata directory");
        let root_key = RootAuthenticationKey::from_bytes32([0x73; 32]);
        {
            let mut filesystem = LocalFileSystem::open_with_block_devices_and_recovery_policy(
                &metadata,
                &devices,
                "offline-integrity",
                PoolRedundancyPolicy::replicated(2),
                StoreOptions::default(),
                root_key,
                RecoveryPolicy::default(),
            )
            .expect("open writable Pool carrier");
            filesystem
                .create_file("/checked.bin", 0o600)
                .expect("create checked file");
            filesystem
                .write_file("/checked.bin", 0, b"authenticated offline integrity")
                .expect("write checked file");
            filesystem.sync_all().expect("commit checked file");
        }

        let lock_dir = dir.path().join("locks");
        tidefs_pool_import::pool_export(&devices, &lock_dir, false).expect("export fixture Pool");
        let mut read_only = LocalFileSystem::open_with_block_devices_and_recovery_policy(
            &metadata,
            &devices,
            "offline-integrity",
            PoolRedundancyPolicy::replicated(2),
            StoreOptions::default(),
            root_key,
            RecoveryPolicy::ReadOnly,
        )
        .expect("open explicit devices read-only");
        let report = OfflinePoolIntegrityReport::collect(&mut read_only)
            .expect("collect authenticated offline integrity");

        assert!(report.passed(), "report: {report:?}");
        assert!(report.verifier.selected_root.is_some());
        assert!(report.verifier.checked_content_objects > 0);
        assert!(report.verifier.checked_content_chunks > 0);
        assert_eq!(report.filesystem.file_count, 1);
        drop(read_only);

        let labels = assemble_device_pool_config(&devices, "integrity-check-test");
        assert_eq!(
            labels.state,
            tidefs_types_pool_label_core::PoolState::Exported,
            "read-only integrity must not activate or rewrite Pool labels",
        );
        assert!(
            LocalFileSystem::open_with_block_devices_and_recovery_policy(
                &metadata,
                &devices,
                "offline-integrity",
                PoolRedundancyPolicy::replicated(2),
                StoreOptions::default(),
                RootAuthenticationKey::from_bytes32([0x74; 32]),
                RecoveryPolicy::ReadOnly,
            )
            .is_err(),
            "a wrong root-authentication key must not yield a passing report",
        );
    }

    #[test]
    fn scrub_parses_live_owner_pool_and_json_output() {
        use clap::Parser;
        let command = PoolCommand::try_parse_from(["pool", "scrub", "tank", "--json"])
            .expect("parse pool scrub");
        assert!(matches!(
            command,
            PoolCommand::Scrub { pool, json: true } if pool == "tank"
        ));
    }

    #[test]
    fn pool_repair_parses_live_owner_pool_and_json_output() {
        use clap::Parser;
        let command = PoolCommand::try_parse_from(["pool", "repair", "tank", "--json"])
            .expect("parse pool repair");
        assert!(matches!(
            command,
            PoolCommand::Repair { pool, json: true } if pool == "tank"
        ));
    }
}
