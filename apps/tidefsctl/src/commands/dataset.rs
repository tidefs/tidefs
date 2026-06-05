//! Dataset subcommands split imported-pool authority from offline access.
//!
//! Pool-name-only dataset commands must route through the runtime owner that
//! imported the pool. Explicit `--devices` are the offline/not-yet-imported
//! escape hatch; if a live owner has published an interface for those devices,
//! the command must use that owner instead of opening storage directly.

use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use tidefs_cluster::dataset_catalog::CatalogDelta;
use tidefs_cluster::pool_lease_client::ClusterLeaseClient;
use tidefs_cluster::pool_protocol::CatalogQueryType;
use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, DatasetType, SyncGuarantee};
use tidefs_dataset_properties;
use tidefs_local_filesystem::{LocalFileSystem, RecoveryPolicy, RootAuthenticationKey};
use tidefs_local_object_store::StoreOptions;
use tidefs_types_dataset_feature_flags_core::{get_feature_class, FeatureClass, FeatureName};

use bincode;

/// Sub-subcommands for `tidefsctl dataset`.
#[derive(Subcommand, Debug)]
pub enum DatasetCommand {
    /// Create a new dataset in the pool-wide catalog
    Create(DatasetCreateArgs),
    /// List datasets in the pool-wide catalog
    List(DatasetListArgs),
    /// Destroy a dataset, removing its catalog entry
    Destroy(DatasetDestroyArgs),
    /// Rename a dataset, preserving its stable DatasetId
    Rename(DatasetRenameArgs),
    /// Enable, disable, or list dataset feature flags through canonical authority
    SetStrategy(DatasetSetStrategyArgs),
    /// Seal a dataset encryption key under a passphrase-derived wrapping key.
    /// Stores the sealed DEK in the pool's keystore for later key rotation.
    SealKey(DatasetSealKeyArgs),
    /// Rotate the pool wrapping key (change passphrase) and re-wrap all
    /// dataset DEKs.  Requires the old passphrase to unwrap existing DEKs
    /// and a new passphrase + salt to re-wrap them.
    RotateKey(DatasetRotateKeyArgs),
    /// Enable all supported-but-not-yet-enabled features in one operation
    Upgrade(DatasetUpgradeArgs),
    /// Get a typed dataset property value with source annotation
    Get(DatasetGetArgs),
    /// Set a typed dataset property value with validation
    Set(DatasetSetArgs),
    /// List all registry properties for a dataset with effective values and sources
    ListProps(DatasetListPropsArgs),
}
/// `dataset create <pool> <name> [--parent <parent>] [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetCreateArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to create
    pub name: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Parent dataset name (default: "root")
    #[arg(long = "parent", default_value = "root")]
    pub parent: String,

    /// Route this operation through cluster authority instead of local pool.
    /// Requires --cluster-node-addr and --cluster-node-id.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    /// Cluster storage-node address. Required when --cluster is set.
    /// Format: host:port.
    #[arg(long = "cluster-node-addr")]
    pub cluster_node_addr: Option<String>,

    /// Node identifier for this cluster client (nonzero).
    /// Required when --cluster is set.
    #[arg(long = "cluster-node-id")]
    pub cluster_node_id: Option<u64>,

    /// Write-acknowledgment sync guarantee: local, remote-copy, or full-redundancy.
    /// Defaults to local (single-node safety).
    #[arg(long = "sync", default_value = "local")]
    pub sync: String,
}
/// `dataset list <pool> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetListArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Route this operation through cluster authority instead of local pool.
    /// Requires --cluster-node-addr and --cluster-node-id.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    /// Cluster storage-node address. Required when --cluster is set.
    /// Format: host:port.
    #[arg(long = "cluster-node-addr")]
    pub cluster_node_addr: Option<String>,

    /// Node identifier for this cluster client (nonzero).
    /// Required when --cluster is set.
    #[arg(long = "cluster-node-id")]
    pub cluster_node_id: Option<u64>,
}
/// `dataset rename <pool> <old-name> <new-name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetRenameArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Current dataset name to rename
    pub old_name: String,

    /// New dataset name
    pub new_name: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Route this operation through cluster authority instead of local pool.
    /// Requires --cluster-node-addr and --cluster-node-id.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    /// Cluster storage-node address. Required when --cluster is set.
    /// Format: host:port.
    #[arg(long = "cluster-node-addr")]
    pub cluster_node_addr: Option<String>,

    /// Node identifier for this cluster client (nonzero).
    /// Required when --cluster is set.
    #[arg(long = "cluster-node-id")]
    pub cluster_node_id: Option<u64>,
}
/// `dataset destroy <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetDestroyArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to destroy
    pub name: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Route this operation through cluster authority instead of local pool.
    /// Requires --cluster-node-addr and --cluster-node-id.
    #[arg(long = "cluster", default_value_t = false)]
    pub cluster: bool,

    /// Cluster storage-node address. Required when --cluster is set.
    /// Format: host:port.
    #[arg(long = "cluster-node-addr")]
    pub cluster_node_addr: Option<String>,

    /// Node identifier for this cluster client (nonzero).
    /// Required when --cluster is set.
    #[arg(long = "cluster-node-id")]
    pub cluster_node_id: Option<u64>,
}
/// `dataset set-strategy <pool> <name> [--devices <dev>...] [--enable <features>] [--disable <features>] [--list] [--class <class>]`
#[derive(Args, Debug)]
pub struct DatasetSetStrategyArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to configure
    pub name: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Comma-separated features to enable (e.g. "org.tidefs:compression_zstd")
    #[arg(long = "enable", value_delimiter = ',')]
    pub enable: Vec<String>,

    /// Comma-separated features to disable (e.g. "org.tidefs:compression_lz4")
    #[arg(long = "disable", value_delimiter = ',')]
    pub disable: Vec<String>,

    /// List currently enabled feature flags
    #[arg(long = "list")]
    pub list: bool,

    /// Feature compatibility class (compat, ro_compat, incompat)
    #[arg(long = "class", default_value = "auto")]
    pub class: String,
}

/// `dataset seal-key <pool> <name> [--devices <dev>...] --passphrase <phrase>`
#[derive(Args, Debug)]
pub struct DatasetSealKeyArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name whose DEK to seal
    pub name: String,

    /// Block devices for offline/not-yet-imported key access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Passphrase for deriving the pool wrapping key
    #[arg(long = "passphrase", short = 'P')]
    pub passphrase: String,
}
/// `dataset rotate-key <pool> [--devices <dev>...] --old-passphrase <phrase> --old-salt <hex> --new-passphrase <phrase>`
#[derive(Args, Debug)]
pub struct DatasetRotateKeyArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Block devices for offline/not-yet-imported key access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Current passphrase (must match existing sealed DEKs)
    #[arg(long = "old-passphrase", short = 'o')]
    pub old_passphrase: String,

    /// Salt used when the keys were originally sealed (hex-encoded, 32 chars)
    #[arg(long = "old-salt")]
    pub old_salt: String,

    /// New passphrase for the rotated wrapping key
    #[arg(long = "new-passphrase", short = 'n')]
    pub new_passphrase: String,
}

/// `dataset upgrade <pool> <name> [--devices <dev>...]`
///
/// Enables all canonical V1 features that are not yet enabled on the dataset.
/// Uses the upgrade table ([`tidefs_dataset_feature_flags::SupportedFeaturesV1`])
/// to determine which features the current software version supports, then
/// enables each supported-but-not-yet-enabled feature with prerequisite checking.
#[derive(Args, Debug)]
pub struct DatasetUpgradeArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to upgrade
    pub name: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,
}

/// `dataset get <pool> <name> <property> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetGetArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to query
    pub name: String,

    /// Property name (e.g. "access.readonly", "layout.recordsize")
    pub property: String,

    /// Block devices for offline/not-yet-imported property access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,
}

/// `dataset set <pool> <name> <property>=<value> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetSetArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to configure
    pub name: String,

    /// Property assignment in key=value form (e.g. "access.readonly=on")
    pub assignment: String,

    /// Block devices for offline/not-yet-imported property access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,
}
/// `dataset list-props <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetListPropsArgs {
    /// Pool name (imported-pool identity; routed through the live owner)
    pub pool: String,

    /// Dataset name to list properties for
    pub name: String,

    /// Block devices for offline/not-yet-imported property access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Filter properties by family (e.g. "access", "layout", "integrity")
    #[arg(long = "family", short = 'f')]
    pub family: Option<String>,
}

/// Dispatch the dataset subcommand.
pub fn handle_dataset(cmd: DatasetCommand) {
    match cmd {
        DatasetCommand::Create(args) => handle_create(args),
        DatasetCommand::List(args) => handle_list(args),
        DatasetCommand::Destroy(args) => handle_destroy(args),
        DatasetCommand::Rename(args) => handle_rename(args),
        DatasetCommand::SetStrategy(args) => handle_set_strategy(args),
        DatasetCommand::SealKey(args) => handle_seal_key(args),
        DatasetCommand::RotateKey(args) => handle_rotate_key(args),
        DatasetCommand::Upgrade(args) => handle_upgrade(args),
        DatasetCommand::Get(args) => handle_get(args),
        DatasetCommand::Set(args) => handle_set(args),
        DatasetCommand::ListProps(args) => handle_list_props(args),
    }
}
fn open_filesystem(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
) -> LocalFileSystem {
    open_filesystem_with_live_args(
        pool,
        devices,
        operation,
        recovery_policy,
        serde_json::Value::Null,
    )
}

fn open_filesystem_with_live_args(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    live_args: serde_json::Value,
) -> LocalFileSystem {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let config = scan_device_pool_config(pool, devs, operation);
        super::live_owner::route_if_owner_exists_for_uuid_with_args(
            "dataset",
            operation,
            pool,
            config.pool_uuid,
            live_args,
        );

        let metadata_dir =
            super::offline_pool::metadata_dir("dataset", operation, &config.pool_uuid);

        let root_auth_key = RootAuthenticationKey::from_environment()
            .unwrap_or_else(|_| RootAuthenticationKey::demo_key());
        return match LocalFileSystem::open_with_block_devices_and_recovery_policy(
            &metadata_dir,
            devs,
            StoreOptions::default(),
            root_auth_key,
            recovery_policy,
        ) {
            Ok(fs) => fs,
            Err(err) => {
                eprintln!(
                    "tidefsctl dataset {operation}: failed to open block-device-backed pool '{pool}' at {}: {err}",
                    metadata_dir.display()
                );
                process::exit(1);
            }
        };
    }

    super::live_owner::route_with_args("dataset", operation, pool, live_args)
}

fn scan_device_pool_config(
    pool: &str,
    devices: &[PathBuf],
    operation: &str,
) -> tidefs_pool_scan::PoolConfig {
    let entries = match tidefs_pool_scan::scan_labels(devices) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("tidefsctl dataset {operation}: pool label scan failed for '{pool}': {err}");
            process::exit(1);
        }
    };
    let config = match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config,
        Err(err) => {
            eprintln!("tidefsctl dataset {operation}: pool assembly failed for '{pool}': {err}");
            process::exit(1);
        }
    };
    if config.pool_name != pool {
        eprintln!(
            "tidefsctl dataset {operation}: devices belong to pool '{}', not '{pool}'",
            config.pool_name
        );
        process::exit(1);
    }
    config
}

/// Derive a stable DatasetId from a dataset name using BLAKE3.
fn dataset_id_from_name(name: &str) -> DatasetId {
    let mut id_bytes = [0u8; 16];
    let hash = blake3::hash(name.as_bytes());
    id_bytes.copy_from_slice(&hash.as_bytes()[..16]);
    DatasetId::from_bytes(id_bytes)
}

// ── Cluster mode shared helpers ─────────────────────────────────────

/// Resolve the pool GUID from device labels. Exits on failure.
fn resolve_cluster_pool_guid(devices: &[std::path::PathBuf], operation: &str) -> [u8; 16] {
    let entries = match tidefs_pool_scan::scan_labels(devices) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!("tidefsctl dataset {operation}: pool label scan failed: {err}");
            process::exit(1);
        }
    };
    match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config.pool_uuid,
        Err(err) => {
            eprintln!("tidefsctl dataset {operation}: pool assembly failed: {err}");
            process::exit(1);
        }
    }
}

/// Validate cluster args and return (node_addr, node_id). Exits on failure.
fn validate_cluster_args<'a>(
    node_addr: &'a Option<String>,
    node_id: Option<u64>,
    operation: &'a str,
) -> (&'a str, u64) {
    let addr = node_addr.as_deref().unwrap_or_else(|| {
        eprintln!("tidefsctl dataset {operation}: --cluster requires --cluster-node-addr");
        process::exit(1);
    });
    let id = node_id.unwrap_or_else(|| {
        eprintln!("tidefsctl dataset {operation}: --cluster requires --cluster-node-id (nonzero)");
        process::exit(1);
    });
    if id == 0 {
        eprintln!("tidefsctl dataset {operation}: --cluster-node-id must be nonzero");
        process::exit(1);
    }
    (addr, id)
}

/// Require devices for cluster mode. Exits if absent.
fn require_devices_for_cluster<'a>(
    devices: Option<&'a [std::path::PathBuf]>,
    operation: &'a str,
) -> &'a [std::path::PathBuf] {
    devices.unwrap_or_else(|| {
        eprintln!("tidefsctl dataset {operation}: --cluster requires --devices");
        process::exit(1);
    })
}

/// Submit a CatalogDelta to the cluster authority and exit on failure.
/// Returns the new catalog version on success.
fn submit_cluster_delta(
    node_addr: &str,
    node_id: u64,
    pool_guid: [u8; 16],
    delta: &CatalogDelta,
    operation: &str,
) -> u64 {
    let delta_bytes = match bincode::serialize(delta) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("tidefsctl dataset {operation}: failed to serialize catalog delta: {e}");
            process::exit(1);
        }
    };
    match ClusterLeaseClient::submit_catalog_delta(node_addr, node_id, pool_guid, delta_bytes) {
        Ok(resp) => {
            if resp.success {
                resp.catalog_version.unwrap_or(0)
            } else {
                let err = resp.error.unwrap_or_else(|| "unknown error".to_string());
                eprintln!("tidefsctl dataset {operation}: cluster refused: {err}");
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("tidefsctl dataset {operation}: cluster transport error: {e}");
            process::exit(1);
        }
    }
}

fn handle_create(args: DatasetCreateArgs) {
    let devices_ref = args.devices.as_deref();
    let name = &args.name;
    let parent = &args.parent;

    if name == "root" {
        eprintln!("tidefsctl dataset create: 'root' dataset cannot be re-created; it is created automatically with the pool");
        process::exit(1);
    }

    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "create");
        let devs = require_devices_for_cluster(devices_ref.map(|d| d), "create");
        let pool_guid = resolve_cluster_pool_guid(devs, "create");

        let full_path = if parent == "root" {
            name.clone()
        } else {
            format!("{parent}/{name}")
        };
        let dataset_id = dataset_id_from_name(&full_path);
        let delta = CatalogDelta::Create {
            path: full_path.clone(),
            dataset_id_bytes: dataset_id.as_bytes().to_vec(),
            dataset_type_u8: DatasetType::Filesystem.to_u8(),
            creation_txg: 1,
            properties: vec![],
            flags_u16: DatasetFlags::default_create().bits(),
        };

        let catalog_version = submit_cluster_delta(node_addr, node_id, pool_guid, &delta, "create");

        println!(
            "dataset '{full_path}' created in clustered pool '{}' (catalog_version={catalog_version})",
            args.pool
        );
        println!("  id={}  parent='{parent}'", format_dataset_id(&dataset_id));
        return;
    }

    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        devices_ref,
        "create",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &args.name,
            "parent": &args.parent,
            "sync": &args.sync,
        }),
    );

    // Check parent exists in the catalog
    if !fs.dataset_catalog().contains(parent) {
        eprintln!(
            "tidefsctl dataset create: parent dataset '{parent}' does not exist in the catalog"
        );
        process::exit(1);
    }

    // Build full path for hierarchical catalog entry
    let full_path = if parent == "root" {
        name.clone()
    } else {
        format!("{parent}/{name}")
    };

    // Check the full path does not already exist
    if fs.dataset_catalog().contains(&full_path) {
        eprintln!("tidefsctl dataset create: dataset '{full_path}' already exists in the catalog");
        process::exit(1);
    }

    let dataset_id = dataset_id_from_name(&full_path);

    let sync_guarantee = match args.sync.as_str() {
        "local" => SyncGuarantee::Local,
        "remote-copy" => SyncGuarantee::RemoteCopy,
        "full-redundancy" => SyncGuarantee::FullRedundancy,
        other => {
            eprintln!("tidefsctl dataset create: invalid --sync value {other}; expected local, remote-copy, or full-redundancy");
            process::exit(1);
        }
    };

    match fs.dataset_catalog_mut().create(
        &full_path,
        dataset_id,
        DatasetType::Filesystem,
        1,
        vec![],
        DatasetFlags::default_create(),
        sync_guarantee,
    ) {
        Ok(()) => {
            println!("dataset '{full_path}' created in pool '{}'", args.pool);
        }
        Err(err) => {
            eprintln!("tidefsctl dataset create: catalog error creating '{full_path}': {err}");
            process::exit(1);
        }
    }

    if let Err(err) = fs.persist_dataset_catalog() {
        eprintln!("tidefsctl dataset create: failed to persist catalog: {err}");
        process::exit(1);
    }

    println!("  id={}  parent='{parent}'", format_dataset_id(&dataset_id));
}
fn handle_list(args: DatasetListArgs) {
    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "list");
        let devs = require_devices_for_cluster(args.devices.as_deref(), "list");
        let pool_guid = resolve_cluster_pool_guid(devs, "list");

        match ClusterLeaseClient::query_catalog(
            node_addr,
            node_id,
            pool_guid,
            CatalogQueryType::ListAll,
            "",
        ) {
            Ok(resp) => {
                if !resp.success {
                    let err = resp.error.unwrap_or_else(|| "unknown error".to_string());
                    eprintln!("tidefsctl dataset list: cluster query failed: {err}");
                    process::exit(1);
                }
                if resp.entries.is_empty() {
                    println!("pool '{}' has no datasets", args.pool);
                } else {
                    let mut sorted: Vec<_> = resp.entries.iter().collect();
                    sorted.sort_by(|a, b| a.path.cmp(&b.path));
                    println!(
                        "pool '{}' datasets (catalog_version={}):",
                        args.pool, resp.catalog_version
                    );
                    for entry in &sorted {
                        let id_str: String = entry
                            .dataset_id_bytes
                            .iter()
                            .take(4)
                            .map(|b| format!("{b:02x}"))
                            .collect();
                        let lc = match entry.lifecycle_state_u8 {
                            0 => "Active",
                            1 => "Destroying",
                            2 => "Destroyed",
                            _ => "???",
                        };
                        println!(
                            "  dataset '{}' id={} type={} state={lc}",
                            entry.path, id_str, entry.dataset_type_u8
                        );
                    }
                }
                return;
            }
            Err(e) => {
                eprintln!("tidefsctl dataset list: cluster transport error: {e}");
                process::exit(1);
            }
        }
    }

    let devices_ref = args.devices.as_deref();
    let fs = open_filesystem(&args.pool, devices_ref, "list", RecoveryPolicy::ReadOnly);
    let catalog = fs.dataset_catalog();

    let entries = catalog.entries();
    if entries.is_empty() {
        println!("pool '{}' has no datasets", args.pool);
        return;
    }

    let mut sorted: Vec<_> = entries.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));

    println!("pool '{}' datasets:", args.pool);
    for (path, id) in &sorted {
        // Format type if available, otherwise show "---" for entries without lifecycle state
        let sg = match catalog.sync_guarantee(path) {
            Ok(g) => g.to_string(),
            Err(_) => "---".to_string(),
        };
        let lc = match catalog.lifecycle_state(path) {
            Ok(state) => format!("{state:?}"),
            Err(_) => "---".to_string(),
        };
        println!(
            "  dataset '{path}' id={} sync={sg} state={lc}",
            format_dataset_id(id)
        );
    }
}
fn handle_rename(args: DatasetRenameArgs) {
    let old_name = &args.old_name;
    let new_name = &args.new_name;

    if old_name == "root" {
        eprintln!("tidefsctl dataset rename: 'root' dataset cannot be renamed");
        process::exit(1);
    }
    if new_name == "root" {
        eprintln!("tidefsctl dataset rename: cannot rename to 'root'");
        process::exit(1);
    }

    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "rename");
        let devs = require_devices_for_cluster(args.devices.as_deref(), "rename");
        let pool_guid = resolve_cluster_pool_guid(devs, "rename");

        let delta = CatalogDelta::Rename {
            old_path: old_name.clone(),
            new_path: new_name.clone(),
        };

        let catalog_version = submit_cluster_delta(node_addr, node_id, pool_guid, &delta, "rename");

        println!(
            "dataset '{old_name}' renamed to '{new_name}' in clustered pool '{}' (catalog_version={catalog_version})",
            args.pool
        );
        return;
    }

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        devices_ref,
        "rename",
        RecoveryPolicy::default(),
        serde_json::json!({
            "old_name": &args.old_name,
            "new_name": &args.new_name,
        }),
    );

    // Verify the old name exists
    if !fs.dataset_catalog().contains(old_name) {
        eprintln!("tidefsctl dataset rename: dataset '{old_name}' does not exist in the catalog");
        process::exit(1);
    }

    // Verify the new name does not already exist
    if fs.dataset_catalog().contains(new_name) {
        eprintln!("tidefsctl dataset rename: dataset '{new_name}' already exists in the catalog");
        process::exit(1);
    }

    match fs.dataset_catalog_mut().rename(old_name, new_name) {
        Ok(()) => {
            println!(
                "dataset '{old_name}' renamed to '{new_name}' in pool '{}'",
                args.pool
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl dataset rename: catalog error renaming '{old_name}' -> '{new_name}': {err}"
            );
            process::exit(1);
        }
    }

    if let Err(err) = fs.persist_dataset_catalog() {
        eprintln!("tidefsctl dataset rename: failed to persist catalog: {err}");
        process::exit(1);
    }
}
fn handle_set_strategy(args: DatasetSetStrategyArgs) {
    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem(
        &args.pool,
        devices_ref,
        "set-strategy",
        RecoveryPolicy::default(),
    );

    // Verify dataset exists in catalog
    if !fs.dataset_catalog().contains(&args.name) {
        eprintln!(
            "tidefsctl dataset set-strategy: dataset '{}' does not exist in the catalog",
            args.name
        );
        process::exit(1);
    }

    // Handle --list
    if args.list {
        let ff = fs.feature_flags();
        if ff.is_empty() {
            println!("dataset '{}' has no feature flags enabled", args.name);
        } else {
            println!("dataset '{}' feature flags:", args.name);
            for (class, name, value) in ff.all_features() {
                println!("  {class}  {name}  ({})", value.to_u8());
            }
        }
        return;
    }

    // Resolve feature class: explicit --class overrides, otherwise the
    // canonical registry determines the class for each feature.  The
    // resolved class applies to all --enable entries in this invocation.
    let feature_class = {
        let explicit_class = match args.class.as_str() {
            "compat" => Some(FeatureClass::Compat),
            "ro_compat" | "ro-compat" => Some(FeatureClass::RoCompat),
            "incompat" => Some(FeatureClass::Incompat),
            "auto" => None,
            other => {
                eprintln!(
                    "tidefsctl dataset set-strategy: unknown feature class '{other}'; expected auto, compat, ro_compat, or incompat"
                );
                process::exit(1);
            }
        };

        // When --class is "auto", resolve per-feature from the registry.
        // Unknown (vendor-extension) features require an explicit --class.
        if let Some(explicit) = explicit_class {
            explicit
        } else if args.enable.is_empty() {
            // No features being enabled; class is irrelevant; use Compat as dummy.
            FeatureClass::Compat
        } else {
            // Resolve from the first enable entry — all entries in one
            // invocation share the same class for simplicity.
            let first = args.enable[0].trim();
            match FeatureName::from_str(first) {
                Some(name) => match get_feature_class(&name) {
                    Some(class) => class,
                    None => {
                        eprintln!(
                            "tidefsctl dataset set-strategy: cannot auto-resolve class for '{first}' (unknown feature); specify --class explicitly"
                        );
                        process::exit(1);
                    }
                },
                None => {
                    eprintln!("tidefsctl dataset set-strategy: invalid feature name '{first}'");
                    process::exit(1);
                }
            }
        }
    };

    let mut changed = false;

    // Enable features
    for feature_str in &args.enable {
        let feature_str = feature_str.trim();
        if feature_str.is_empty() {
            continue;
        }
        match FeatureName::from_str(feature_str) {
            Some(name) => {
                match fs
                    .feature_flags_mut()
                    .enable_feature_with_prereqs(name.clone(), feature_class)
                {
                    Ok(()) => {
                        println!("enabled feature '{feature_str}' (class: {feature_class})");
                        changed = true;
                    }
                    Err(e) => {
                        eprintln!(
                            "tidefsctl dataset set-strategy: failed to enable '{feature_str}': {e}"
                        );
                        process::exit(1);
                    }
                }
            }
            None => {
                eprintln!(
                    "tidefsctl dataset set-strategy: invalid feature name '{feature_str}'; expected format org.tidefs:<name>"
                );
                process::exit(1);
            }
        }
    }

    // Disable features
    for feature_str in &args.disable {
        let feature_str = feature_str.trim();
        if feature_str.is_empty() {
            continue;
        }
        match FeatureName::from_str(feature_str) {
            Some(name) => match fs.feature_flags_mut().disable_feature(&name) {
                Ok(()) => {
                    println!("disabled feature '{feature_str}'");
                    changed = true;
                }
                Err(e) => {
                    eprintln!(
                        "tidefsctl dataset set-strategy: failed to disable '{feature_str}': {e}"
                    );
                    process::exit(1);
                }
            },
            None => {
                eprintln!(
                    "tidefsctl dataset set-strategy: invalid feature name '{feature_str}'; expected format org.tidefs:<name>"
                );
                process::exit(1);
            }
        }
    }

    // Persist feature flags if any changes were made
    if changed {
        match fs.persist_feature_flags() {
            Ok(()) => {
                eprintln!("feature flags persisted for dataset '{}'", args.name);
                // Refresh runtime policies so new writes use the updated
                // compression/dedup settings immediately, without remount.
                fs.refresh_policies_from_features();
            }
            Err(e) => {
                eprintln!("tidefsctl dataset set-strategy: failed to persist feature flags: {e}");
                process::exit(1);
            }
        }
    }
}
/// Enable all supported features that are not yet enabled on the dataset.
///
/// Uses [`tidefs_dataset_feature_flags::FeatureFlags::supported_features`]
/// (the upgrade table) to enumerate every feature the current software version
/// understands, then enables each one that is not already active.  Features
/// are enabled with prerequisite checking (transitive dependencies are
/// automatically satisfied in dependency order).
fn handle_upgrade(args: DatasetUpgradeArgs) {
    use tidefs_dataset_feature_flags::SupportedFeaturesV1;
    use tidefs_types_dataset_feature_flags_core::get_feature_class;

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem(
        &args.pool,
        devices_ref,
        "upgrade",
        RecoveryPolicy::default(),
    );

    // Verify dataset exists in catalog
    if !fs.dataset_catalog().contains(&args.name) {
        eprintln!(
            "tidefsctl dataset upgrade: dataset '{}' does not exist in the catalog",
            args.name
        );
        process::exit(1);
    }

    let supported = SupportedFeaturesV1::current();
    let ff = fs.feature_flags();
    let mut enabled_count = 0u32;
    let mut skipped_count = 0u32;
    let mut failed: Vec<(String, String)> = Vec::new();

    // Collect features to enable: all supported features not already active.
    let to_enable: Vec<_> = supported
        .as_slice()
        .iter()
        .filter(|name| !ff.is_enabled(name))
        .cloned()
        .collect();

    if to_enable.is_empty() {
        println!(
            "dataset '{}': all {} supported features are already enabled",
            args.name,
            supported.len()
        );
        return;
    }

    println!(
        "dataset '{}': upgrading from {} enabled to {} supported features...",
        args.name,
        ff.len(),
        supported.len()
    );

    for name in &to_enable {
        let class = match get_feature_class(name) {
            Some(c) => c,
            None => {
                // Unknown features are part of the supported set by definition;
                // skip with a note (shouldn't happen for canonical features).
                skipped_count += 1;
                continue;
            }
        };

        match fs
            .feature_flags_mut()
            .enable_feature_with_prereqs(name.clone(), class)
        {
            Ok(()) => {
                println!("  enabled {name} ({class})");
                enabled_count += 1;
            }
            Err(e) => {
                let msg = format!("{e}");
                eprintln!("  FAILED {name} ({class}) : {msg}");
                failed.push((name.to_string(), msg));
            }
        }
    }

    // Persist if any features were enabled
    if enabled_count > 0 {
        match fs.persist_feature_flags() {
            Ok(()) => {
                eprintln!("feature flags persisted for dataset '{}'", args.name);
                fs.refresh_policies_from_features();
            }
            Err(e) => {
                eprintln!("tidefsctl dataset upgrade: failed to persist feature flags: {e}");
                process::exit(1);
            }
        }
    }

    println!(
        "dataset '{}' upgrade complete: {} enabled, {} skipped, {} failed",
        args.name,
        enabled_count,
        skipped_count,
        failed.len()
    );

    if !failed.is_empty() {
        eprintln!("Some features could not be enabled:");
        for (name, reason) in &failed {
            eprintln!("  {name}: {reason}");
        }
        process::exit(1);
    }
}

fn handle_get(args: DatasetGetArgs) {
    let fs = open_filesystem_with_live_args(
        &args.pool,
        args.devices.as_deref(),
        "get",
        RecoveryPolicy::ReadOnly,
        serde_json::json!({
            "name": &args.name,
            "property": &args.property,
        }),
    );

    let path = args.name.as_str();
    // Resolve properties with full parent-chain inheritance.
    let effective = match fs.dataset_catalog().get_properties_with_inheritance(&path) {
        Ok(props) => props,
        Err(e) => {
            eprintln!(
                "tidefsctl dataset get: cannot read properties for '{}': {e}",
                &args.name
            );
            process::exit(1);
        }
    };

    let registry = tidefs_dataset_properties::build_registry();
    let key = tidefs_dataset_properties::PropertyKey::new(&args.property);

    // Verify the property is known.
    if tidefs_dataset_properties::lookup_property(&registry, &key).is_none() {
        eprintln!(
            "tidefsctl dataset get: unknown property '{}'",
            &args.property
        );
        process::exit(1);
    }

    // Show the effective value with source.
    match effective.get(&key) {
        Some(entry) => {
            println!("property:  {}", &args.property);
            println!("value:     {}", entry.value);
            println!("source:    {}", entry.source);
        }
        None => {
            // Should not happen since get_properties_with_inheritance fills all registry keys.
            eprintln!(
                "tidefsctl dataset get: internal error resolving '{}'",
                &args.property
            );
            process::exit(1);
        }
    }
}
fn handle_set(args: DatasetSetArgs) {
    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        args.devices.as_deref(),
        "set",
        RecoveryPolicy::RepairWriteback,
        serde_json::json!({
            "name": &args.name,
            "assignment": &args.assignment,
        }),
    );

    // Parse the assignment: key=value
    let (prop_name, prop_val_str) = match args.assignment.split_once('=') {
        Some((k, v)) => (k.trim(), v.trim()),
        None => {
            eprintln!(
                "tidefsctl dataset set: invalid assignment '{}' (expected key=value)",
                &args.assignment
            );
            process::exit(1);
        }
    };

    if prop_name.is_empty() {
        eprintln!("tidefsctl dataset set: property name must not be empty");
        process::exit(1);
    }

    let registry = tidefs_dataset_properties::build_registry();
    let key = tidefs_dataset_properties::PropertyKey::new(prop_name);

    let def = match tidefs_dataset_properties::lookup_property(&registry, &key) {
        Some(def) => def,
        None => {
            eprintln!("tidefsctl dataset set: unknown property '{}'", prop_name);
            process::exit(1);
        }
    };

    // Check if the user is clearing the override (value="-" or empty).
    let is_clear = prop_val_str.is_empty() || prop_val_str == "-";

    let value = if is_clear {
        tidefs_dataset_properties::PropertyValue::None
    } else {
        tidefs_dataset_properties::PropertySet::parse_value_from_str(prop_val_str)
    };

    // Validate the proposed value against the registry.
    let path = args.name.as_str();
    let existing_props = fs
        .dataset_catalog()
        .get_properties(&path)
        .unwrap_or_default();

    if let Err(verr) = tidefs_dataset_properties::validate_set(&key, &value, def, &existing_props) {
        eprintln!("tidefsctl dataset set: validation failed: {verr}");
        process::exit(1);
    }

    // Apply the change: clear or set.
    let mut props = existing_props;
    if is_clear {
        props.remove_local_override(&key);
    } else {
        props.set_local(key.clone(), value.clone());
    }

    match fs.dataset_catalog_mut().set_properties(&path, &props) {
        Ok(()) => {
            if let Err(e) = fs.persist_dataset_catalog() {
                eprintln!("tidefsctl dataset set: property set but catalog persist failed: {e}");
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
        Err(e) => {
            eprintln!(
                "tidefsctl dataset set: cannot write properties for '{}': {e}",
                &args.name
            );
            process::exit(1);
        }
    }
}

fn handle_list_props(args: DatasetListPropsArgs) {
    let fs = open_filesystem_with_live_args(
        &args.pool,
        args.devices.as_deref(),
        "list-props",
        RecoveryPolicy::ReadOnly,
        serde_json::json!({
            "name": &args.name,
            "family": args.family.as_deref(),
        }),
    );

    let path = args.name.as_str();
    let props = match fs.dataset_catalog().get_properties(&path) {
        Ok(props) => props,
        Err(e) => {
            eprintln!(
                "tidefsctl dataset list-props: cannot read properties for '{}': {e}",
                &args.name
            );
            process::exit(1);
        }
    };

    let registry = tidefs_dataset_properties::build_registry();

    // Filter by family if requested.
    let defs: Vec<_> = if let Some(ref family_str) = args.family {
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
                eprintln!("tidefsctl dataset list-props: unknown family '{}'", other);
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

    // Print header.
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
            tidefs_dataset_properties::PropertySource::Inherited { parent_dataset_id } => {
                // Format as string inline.
                &*format!("inherited from {}", parent_dataset_id).leak()
            }
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
fn handle_destroy(args: DatasetDestroyArgs) {
    let name = &args.name;

    if name == "root" {
        eprintln!("tidefsctl dataset destroy: 'root' dataset cannot be destroyed");
        process::exit(1);
    }

    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "destroy");
        let devs = require_devices_for_cluster(args.devices.as_deref(), "destroy");
        let pool_guid = resolve_cluster_pool_guid(devs, "destroy");

        let delta = CatalogDelta::Destroy { path: name.clone() };

        let catalog_version =
            submit_cluster_delta(node_addr, node_id, pool_guid, &delta, "destroy");

        println!(
            "dataset '{name}' destroyed in clustered pool '{}' (catalog_version={catalog_version})",
            args.pool
        );
        return;
    }

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        devices_ref,
        "destroy",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &args.name,
        }),
    );

    // Check dataset exists
    if !fs.dataset_catalog().contains(name) {
        eprintln!("tidefsctl dataset destroy: dataset '{name}' does not exist in the catalog");
        process::exit(1);
    }

    // Check for children
    let children = match fs.dataset_catalog().list_children(name) {
        Ok(c) => c,
        Err(err) => {
            eprintln!(
                "tidefsctl dataset destroy: catalog error listing children of '{name}': {err}"
            );
            process::exit(1);
        }
    };
    if !children.is_empty() {
        eprintln!(
            "tidefsctl dataset destroy: dataset '{name}' has {} child(ren) and cannot be destroyed",
            children.len()
        );
        process::exit(1);
    }

    match fs.dataset_catalog_mut().destroy(name) {
        Ok(()) => {
            println!("dataset '{name}' destroyed");
        }
        Err(err) => {
            eprintln!("tidefsctl dataset destroy: catalog error destroying '{name}': {err}");
            process::exit(1);
        }
    }

    if let Err(err) = fs.persist_dataset_catalog() {
        eprintln!("tidefsctl dataset destroy: failed to persist catalog: {err}");
        process::exit(1);
    }
}

/// Format a DatasetId for compact CLI display (first 8 hex chars of UUID).
fn format_dataset_id(id: &DatasetId) -> String {
    id.to_string().chars().take(8).collect()
}

// ── seal-key handler ─────────────────────────────────────────────────

fn handle_seal_key(args: DatasetSealKeyArgs) {
    use tidefs_encryption::key_hierarchy::{DatasetDEK, PoolWrappingKey};
    use tidefs_encryption::key_manager::{KeyManager, KeyStore};
    use tidefs_local_object_store::StoreOptions;

    // Generate a random salt for the wrapping key derivation.
    let salt = PoolWrappingKey::generate_salt();

    // Derive the pool wrapping key from the passphrase + salt.
    let wk = match PoolWrappingKey::derive(&args.passphrase, &salt) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("tidefsctl dataset seal-key: failed to derive wrapping key: {e}");
            process::exit(1);
        }
    };

    // Generate a fresh per-dataset DEK.
    let dek = DatasetDEK::generate();

    // Seal the DEK under the wrapping key.
    let sealed = match KeyManager::seal_dek(&dek, &wk, &args.name, 1) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tidefsctl dataset seal-key: failed to seal DEK: {e}");
            process::exit(1);
        }
    };

    // Open the keystore at the pool path.
    let devices_ref = args.devices.as_deref();
    let pool_path = resolve_pool_path(&args.pool, devices_ref, "seal-key");

    let mut keystore = match KeyStore::open_with_options(&pool_path, StoreOptions::default(), salt)
    {
        Ok(ks) => ks,
        Err(e) => {
            eprintln!(
                "tidefsctl dataset seal-key: failed to open keystore at {}: {e}",
                pool_path.display()
            );
            process::exit(1);
        }
    };

    if let Err(e) = keystore.store_sealed_dek(&sealed) {
        eprintln!("tidefsctl dataset seal-key: failed to store sealed DEK: {e}");
        process::exit(1);
    }

    let salt_hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "dataset '{}' encryption key sealed (kek_generation=1)",
        args.name
    );
    println!("  salt: {salt_hex}");
    println!("  save this salt; it is required for key rotation");
}

// ── rotate-key handler ───────────────────────────────────────────────

fn handle_rotate_key(args: DatasetRotateKeyArgs) {
    use tidefs_encryption::key_hierarchy::PoolWrappingKey;
    use tidefs_encryption::key_manager::{KeyRotation, KeyStore};
    use tidefs_local_object_store::StoreOptions;

    // Decode the old salt from hex.
    let old_salt = match hex_to_salt(&args.old_salt) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tidefsctl dataset rotate-key: invalid --old-salt: {e}");
            process::exit(1);
        }
    };

    // Generate a fresh salt for the new wrapping key.
    let new_salt = PoolWrappingKey::generate_salt();

    // Open the keystore at the pool path with the old salt.
    let devices_ref = args.devices.as_deref();
    let pool_path = resolve_pool_path(&args.pool, devices_ref, "rotate-key");

    let mut keystore =
        match KeyStore::open_with_options(&pool_path, StoreOptions::default(), old_salt) {
            Ok(ks) => ks,
            Err(e) => {
                eprintln!(
                    "tidefsctl dataset rotate-key: failed to open keystore at {}: {e}",
                    pool_path.display()
                );
                process::exit(1);
            }
        };

    // Verify there are datasets to rotate.
    let datasets = match keystore.list_datasets() {
        Ok(ds) => ds,
        Err(e) => {
            eprintln!("tidefsctl dataset rotate-key: failed to list datasets: {e}");
            process::exit(1);
        }
    };

    if datasets.is_empty() {
        eprintln!(
            "tidefsctl dataset rotate-key: no datasets with sealed DEKs in pool '{}'",
            args.pool
        );
        process::exit(1);
    }

    let stats = match KeyRotation::rekey_wrapping_key(
        &args.old_passphrase,
        &args.new_passphrase,
        &new_salt,
        &mut keystore,
    ) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("tidefsctl dataset rotate-key: key rotation failed: {e}");
            eprintln!(
                "  (verify the old passphrase and salt match the original seal-key invocation)"
            );
            process::exit(1);
        }
    };

    let new_salt_hex: String = new_salt.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "key rotation complete: {} dataset(s) re-wrapped",
        stats.keys_rotated
    );
    println!("  new salt: {new_salt_hex}");
    println!("  save this salt for future rotations");
}

// ── helpers ──────────────────────────────────────────────────────────

/// Resolve explicit offline pool storage to a filesystem path suitable for opening a
/// [`tidefs_encryption::key_manager::KeyStore`].
///
/// Pool-name-only key commands must use the imported-pool owner client, not
/// reopen the path named by the pool identity.
fn resolve_pool_path(pool: &str, devices: Option<&[PathBuf]>, operation: &str) -> PathBuf {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let config = scan_device_pool_config(pool, devs, operation);
        super::live_owner::route_if_owner_exists_for_uuid_with_args(
            "dataset",
            operation,
            pool,
            config.pool_uuid,
            serde_json::Value::Null,
        );

        return super::offline_pool::metadata_dir("dataset", operation, &config.pool_uuid);
    }

    super::live_owner::route("dataset", operation, pool)
}
/// Decode a hex-encoded 16-byte salt string into `[u8; SALT_LEN]`.
fn hex_to_salt(hex: &str) -> Result<[u8; tidefs_encryption::key_hierarchy::SALT_LEN], String> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return Err(format!(
            "expected 32 hex chars (16 bytes), got {}",
            hex.len()
        ));
    }
    let mut salt = [0u8; tidefs_encryption::key_hierarchy::SALT_LEN];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        if chunk.len() != 2 {
            return Err("odd number of hex characters".to_string());
        }
        let byte = u8::from_str_radix(
            std::str::from_utf8(chunk).map_err(|_| "invalid UTF-8 in hex string".to_string())?,
            16,
        )
        .map_err(|e| format!("invalid hex byte at position {}: {e}", i * 2))?;
        salt[i] = byte;
    }
    Ok(salt)
}

#[cfg(test)]
mod key_rotation_tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_encryption::key_hierarchy::{DatasetDEK, PoolWrappingKey};
    use tidefs_encryption::key_manager::{KeyManager, KeyRotation, KeyStore};
    use tidefs_local_object_store::StoreOptions;

    /// Full product-path integration test: seal DEK, rotate wrapping key,
    /// verify the DEK is recoverable after rotation.
    #[test]
    fn seal_then_rotate_then_verify_dek_recoverable() {
        let dir = TempDir::new().unwrap();
        let pool_path = dir.path();

        // Phase 1: Create keystore and seal a DEK.
        let salt = PoolWrappingKey::generate_salt();
        let wk_old = PoolWrappingKey::derive("initial passphrase", &salt).unwrap();
        let dek = DatasetDEK::generate();

        let sealed = KeyManager::seal_dek(&dek, &wk_old, "mydataset", 1).unwrap();

        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        // Phase 2: Rotate the wrapping key.
        let new_salt = PoolWrappingKey::generate_salt();
        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();

            let datasets = ks.list_datasets().unwrap();
            assert_eq!(datasets.len(), 1);
            assert_eq!(datasets[0], "mydataset");

            let stats = KeyRotation::rekey_wrapping_key(
                "initial passphrase",
                "rotated passphrase",
                &new_salt,
                &mut ks,
            )
            .unwrap();
            assert_eq!(stats.keys_rotated, 1);
        }

        // Phase 3: Verify the DEK is recoverable with the new wrapping key.
        {
            let store_opts = StoreOptions::test_fast();
            let ks = KeyStore::open_with_options(pool_path, store_opts, new_salt).unwrap();

            let loaded = ks.load_sealed_dek("mydataset").unwrap().unwrap();
            assert_eq!(loaded.kek_generation, 2); // was 1, incremented by rotation

            let wk_new = PoolWrappingKey::derive("rotated passphrase", &new_salt).unwrap();
            let unsealed = KeyManager::unseal_dek(&loaded, &wk_new).unwrap();
            assert_eq!(dek.as_bytes(), unsealed.as_bytes());

            // Old wrapping key should no longer work.
            let wk_old2 = PoolWrappingKey::derive("initial passphrase", &salt).unwrap();
            assert!(KeyManager::unseal_dek(&loaded, &wk_old2).is_err());
        }
    }

    /// Verify that rotation fails with wrong old passphrase.
    #[test]
    fn rotate_with_wrong_old_passphrase_fails() {
        let dir = TempDir::new().unwrap();
        let pool_path = dir.path();

        let salt = PoolWrappingKey::generate_salt();
        let wk = PoolWrappingKey::derive("correct", &salt).unwrap();
        let dek = DatasetDEK::generate();
        let sealed = KeyManager::seal_dek(&dek, &wk, "ds", 1).unwrap();

        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        let new_salt = PoolWrappingKey::generate_salt();
        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();

            let result = KeyRotation::rekey_wrapping_key(
                "wrong passphrase",
                "new passphrase",
                &new_salt,
                &mut ks,
            );
            assert!(result.is_err());
        }

        // DEK still recoverable with old key.
        {
            let store_opts = StoreOptions::test_fast();
            let ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            let loaded = ks.load_sealed_dek("ds").unwrap().unwrap();
            assert_eq!(loaded.kek_generation, 1); // unchanged
            let unsealed = KeyManager::unseal_dek(&loaded, &wk).unwrap();
            assert_eq!(dek.as_bytes(), unsealed.as_bytes());
        }
    }

    /// Rotation is idempotent: running it twice with the same credentials
    /// succeeds both times.
    #[test]
    fn rotate_twice_succeeds() {
        let dir = TempDir::new().unwrap();
        let pool_path = dir.path();

        let salt = PoolWrappingKey::generate_salt();
        let wk1 = PoolWrappingKey::derive("p1", &salt).unwrap();
        let dek = DatasetDEK::generate();
        let sealed = KeyManager::seal_dek(&dek, &wk1, "ds", 1).unwrap();

        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            ks.store_sealed_dek(&sealed).unwrap();
        }

        let salt2 = PoolWrappingKey::generate_salt();
        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            KeyRotation::rekey_wrapping_key("p1", "p2", &salt2, &mut ks).unwrap();
        }

        let salt3 = PoolWrappingKey::generate_salt();
        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt2).unwrap();
            let stats = KeyRotation::rekey_wrapping_key("p2", "p3", &salt3, &mut ks).unwrap();
            assert_eq!(stats.keys_rotated, 1);
        }

        // Recoverable with p3/salt3
        {
            let store_opts = StoreOptions::test_fast();
            let ks = KeyStore::open_with_options(pool_path, store_opts, salt3).unwrap();
            let loaded = ks.load_sealed_dek("ds").unwrap().unwrap();
            assert_eq!(loaded.kek_generation, 3);
            let wk3 = PoolWrappingKey::derive("p3", &salt3).unwrap();
            let unsealed = KeyManager::unseal_dek(&loaded, &wk3).unwrap();
            assert_eq!(dek.as_bytes(), unsealed.as_bytes());
        }
    }

    /// Multiple datasets all get rotated together.
    #[test]
    fn rotate_multiple_datasets() {
        let dir = TempDir::new().unwrap();
        let pool_path = dir.path();

        let salt = PoolWrappingKey::generate_salt();
        let wk_old = PoolWrappingKey::derive("start", &salt).unwrap();
        let dek = DatasetDEK::generate();

        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            for i in 0..5 {
                let sealed = KeyManager::seal_dek(&dek, &wk_old, &format!("ds-{i}"), 1).unwrap();
                ks.store_sealed_dek(&sealed).unwrap();
            }
        }

        let new_salt = PoolWrappingKey::generate_salt();
        {
            let store_opts = StoreOptions::test_fast();
            let mut ks = KeyStore::open_with_options(pool_path, store_opts, salt).unwrap();
            let stats =
                KeyRotation::rekey_wrapping_key("start", "finish", &new_salt, &mut ks).unwrap();
            assert_eq!(stats.keys_rotated, 5);
        }

        {
            let store_opts = StoreOptions::test_fast();
            let ks = KeyStore::open_with_options(pool_path, store_opts, new_salt).unwrap();
            let wk_new = PoolWrappingKey::derive("finish", &new_salt).unwrap();
            let mut ds = ks.list_datasets().unwrap();
            ds.sort();
            assert_eq!(ds.len(), 5);

            for i in 0..5 {
                let loaded = ks.load_sealed_dek(&format!("ds-{i}")).unwrap().unwrap();
                assert_eq!(loaded.kek_generation, 2);
                let unsealed = KeyManager::unseal_dek(&loaded, &wk_new).unwrap();
                assert_eq!(dek.as_bytes(), unsealed.as_bytes());
            }
        }
    }

    /// hex_to_salt roundtrip.
    #[test]
    fn hex_to_salt_roundtrip() {
        let salt = PoolWrappingKey::generate_salt();
        let hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
        let decoded = hex_to_salt(&hex).unwrap();
        assert_eq!(salt, decoded);
    }

    /// hex_to_salt rejects bad input.
    #[test]
    fn hex_to_salt_rejects_bad_input() {
        assert!(hex_to_salt("too-short").is_err());
        assert!(hex_to_salt("").is_err());
        assert!(hex_to_salt(&"g".repeat(32)).is_err()); // non-hex chars
        assert!(hex_to_salt(&"a".repeat(33)).is_err()); // wrong length
    }
}
