// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Dataset subcommands split imported-pool authority from offline access.
//!
//! Pool-name-only dataset commands must route through the runtime owner that
//! imported the pool. Explicit `--devices` are the offline/not-yet-imported
//! escape hatch; if a live owner has published an interface for those devices,
//! the command must use that owner instead of opening storage directly.

use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand, ValueEnum};
use tidefs_cluster::dataset_catalog::CatalogDelta;
use tidefs_cluster::pool_lease_client::ClusterLeaseClient;
use tidefs_cluster::pool_protocol::CatalogQueryType;
use tidefs_dataset_lifecycle::{
    DatasetCatalog, DatasetFlags, DatasetId, DatasetType, SyncGuarantee,
};
use tidefs_dataset_properties::{self, PropertyKey, PropertySet, PropertyValue};
use tidefs_local_filesystem::{FileSystemStatfs, LocalFileSystem, RecoveryPolicy};
use tidefs_local_object_store::StoreOptions;
use tidefs_types_dataset_feature_flags_core::{get_feature_class, FeatureClass, FeatureName};
use tidefs_vfs_engine::{LivePoolAdminArg, LivePoolAdminArgs};

use bincode;

use crate::parser::{self, DatasetTarget, PropertyAssignment};

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

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum DatasetTypeArg {
    Filesystem,
    Volume,
    Snapshot,
}

impl DatasetTypeArg {
    fn to_dataset_type(self) -> DatasetType {
        match self {
            Self::Filesystem => DatasetType::Filesystem,
            Self::Volume => DatasetType::Volume,
            Self::Snapshot => DatasetType::Snapshot,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Filesystem => "filesystem",
            Self::Volume => "volume",
            Self::Snapshot => "snapshot",
        }
    }
}

impl std::fmt::Display for DatasetTypeArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DatasetListRow {
    pool: String,
    path: String,
    dataset_type: DatasetType,
    used_bytes: Option<u64>,
    available_bytes: Option<u64>,
    mountpoint: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DatasetCapacityProjection {
    used_bytes: Option<u64>,
    available_bytes: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DestroyAdmission {
    child_count: usize,
    snapshot_count: usize,
    live_mount: bool,
}

impl DestroyAdmission {
    fn has_hazards(&self) -> bool {
        self.child_count > 0 || self.snapshot_count > 0 || self.live_mount
    }

    fn hazards(&self) -> Vec<String> {
        let mut hazards = Vec::new();
        if self.child_count > 0 {
            hazards.push(format!("{} child dataset(s)", self.child_count));
        }
        if self.snapshot_count > 0 {
            hazards.push(format!("{} snapshot(s)", self.snapshot_count));
        }
        if self.live_mount {
            hazards.push("a live mount".to_string());
        }
        hazards
    }
}

/// `dataset create <pool>/<name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetCreateArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Mountpoint metadata to pass to the live owner
    #[arg(long = "mountpoint", value_name = "PATH")]
    pub mountpoint: Option<PathBuf>,

    /// Dataset type to create
    #[arg(long = "type", value_enum, default_value_t = DatasetTypeArg::Filesystem)]
    pub dataset_type: DatasetTypeArg,

    /// Initial dataset property in key=value form
    #[arg(long = "property", value_name = "KEY=VALUE")]
    pub properties: Vec<String>,

    /// Canonical dataset feature flag to request at creation
    #[arg(
        long = "feature",
        alias = "feature-flag",
        value_name = "FEATURE",
        value_delimiter = ','
    )]
    pub features: Vec<String>,

    /// Emit machine-parseable JSON
    #[arg(long = "json")]
    pub json: bool,

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
/// `dataset list [-p <pool>] [-t <type>] [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetListArgs {
    /// Pool name filter (imported-pool identity; routed through the live owner)
    #[arg(short = 'p', long = "pool", value_name = "POOL")]
    pub pool: Option<String>,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Dataset type filter
    #[arg(short = 't', long = "type", value_enum)]
    pub dataset_type: Option<DatasetTypeArg>,

    /// Emit machine-parseable JSON
    #[arg(long = "json")]
    pub json: bool,

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
/// `dataset destroy <pool>/<name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetDestroyArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Block devices for offline/not-yet-imported catalog access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Required when the dataset has children, snapshots, or a live mount
    #[arg(long = "force")]
    pub force: bool,

    /// Emit machine-parseable JSON
    #[arg(long = "json")]
    pub json: bool,

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

/// `dataset get <pool>/<name> <property> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetGetArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Property name (e.g. "access.readonly", "layout.recordsize")
    pub property: String,

    /// Block devices for offline/not-yet-imported property access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Emit machine-parseable JSON
    #[arg(long = "json")]
    pub json: bool,
}

/// `dataset set <pool>/<name> <property>=<value> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct DatasetSetArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Property assignment in key=value form (e.g. "access.readonly=on")
    pub assignment: String,

    /// Block devices for offline/not-yet-imported property access
    #[arg(short = 'd', long = "devices", num_args = 1..)]
    pub devices: Option<Vec<PathBuf>>,

    /// Emit machine-parseable JSON
    #[arg(long = "json")]
    pub json: bool,
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
fn open_filesystem_with_live_args(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    json: bool,
    live_args: LivePoolAdminArgs,
) -> LocalFileSystem {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let config = scan_device_pool_config(pool, devs, operation);
        super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
            "dataset",
            operation,
            pool,
            config.pool_uuid,
            config.state == tidefs_types_pool_label_core::PoolState::Active,
            json,
            live_args,
        );

        let metadata_dir =
            super::offline_pool::metadata_dir("dataset", operation, &config.pool_uuid);

        let root_auth_key = super::root_authentication_key_or_exit(&format!("dataset {operation}"));
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

    super::live_owner::route_with_format_and_args("dataset", operation, pool, json, live_args)
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

fn exit_dataset_error(operation: &str, message: impl Into<String>, json: bool) -> ! {
    let message = message.into();
    if json {
        let out = serde_json::json!({
            "ok": false,
            "operation": operation,
            "error": message,
        });
        print_json_or_exit(out);
    } else {
        eprintln!("tidefsctl dataset {operation}: {message}");
    }
    process::exit(1);
}

fn print_json_or_exit(value: serde_json::Value) {
    match serde_json::to_string_pretty(&value) {
        Ok(text) => println!("{text}"),
        Err(err) => {
            eprintln!("tidefsctl dataset: failed to encode JSON output: {err}");
            process::exit(1);
        }
    }
}

fn parse_target_or_exit(raw: &str, operation: &str, json: bool) -> DatasetTarget {
    parser::parse_dataset_target(raw).unwrap_or_else(|err| exit_dataset_error(operation, err, json))
}

fn parse_pool_or_exit(raw: &str, operation: &str, json: bool) -> String {
    parser::parse_pool_name(raw).unwrap_or_else(|err| exit_dataset_error(operation, err, json))
}

fn parse_property_key_or_exit(raw: &str, operation: &str, json: bool) -> String {
    parser::parse_property_key(raw).unwrap_or_else(|err| exit_dataset_error(operation, err, json))
}

fn parse_property_assignment_or_exit(raw: &str, operation: &str, json: bool) -> PropertyAssignment {
    parser::parse_property_assignment(raw)
        .unwrap_or_else(|err| exit_dataset_error(operation, err, json))
}

fn parse_property_assignments_or_exit(
    raw_values: &[String],
    operation: &str,
    json: bool,
) -> Vec<PropertyAssignment> {
    let mut assignments = Vec::with_capacity(raw_values.len());
    let mut seen = std::collections::BTreeSet::new();
    for raw in raw_values {
        let assignment = parse_property_assignment_or_exit(raw, operation, json);
        if !seen.insert(assignment.key.clone()) {
            exit_dataset_error(
                operation,
                format!("duplicate dataset property key: {}", assignment.key),
                json,
            );
        }
        assignments.push(assignment);
    }
    assignments
}

fn parse_feature_names_or_exit(raw_values: &[String], operation: &str, json: bool) -> Vec<String> {
    let mut features = Vec::with_capacity(raw_values.len());
    let mut seen = std::collections::BTreeSet::new();
    for raw in raw_values {
        let feature = parser::parse_dataset_feature_name(raw)
            .unwrap_or_else(|err| exit_dataset_error(operation, err, json));
        if !seen.insert(feature.clone()) {
            exit_dataset_error(
                operation,
                format!("duplicate dataset feature flag: {feature}"),
                json,
            );
        }
        features.push(feature);
    }
    features
}

fn parse_sync_or_exit(raw: &str, operation: &str, json: bool) -> SyncGuarantee {
    match raw {
        "local" => SyncGuarantee::Local,
        "remote-copy" => SyncGuarantee::RemoteCopy,
        "full-redundancy" => SyncGuarantee::FullRedundancy,
        other => exit_dataset_error(
            operation,
            format!(
                "invalid --sync value {other}; expected local, remote-copy, or full-redundancy"
            ),
            json,
        ),
    }
}

fn create_parent_and_leaf(path: &str) -> (String, &str) {
    let (parent, leaf) = parser::dataset_parent_and_leaf(path);
    (parent.unwrap_or("root").to_string(), leaf)
}

fn property_set_from_assignments(assignments: &[PropertyAssignment]) -> PropertySet {
    let mut properties = PropertySet::new();
    for assignment in assignments {
        if assignment.clear {
            continue;
        }
        properties.set_local(PropertyKey::new(&assignment.key), assignment.value.clone());
    }
    properties
}

fn property_assignments_json(assignments: &[PropertyAssignment]) -> Vec<serde_json::Value> {
    assignments
        .iter()
        .map(|assignment| {
            serde_json::json!({
                "key": assignment.key.as_str(),
                "value": property_value_json(&assignment.value),
                "display_value": assignment.value.to_string(),
                "raw_value": assignment.raw_value.as_str(),
                "clear": assignment.clear,
            })
        })
        .collect()
}

fn property_assignments_live_admin_args(
    assignments: &[PropertyAssignment],
) -> Vec<LivePoolAdminArg> {
    assignments
        .iter()
        .map(property_assignment_live_admin_arg)
        .collect()
}

fn property_assignment_live_admin_arg(assignment: &PropertyAssignment) -> LivePoolAdminArg {
    LivePoolAdminArg::Object(
        [
            (
                "key".to_string(),
                LivePoolAdminArg::String(assignment.key.clone()),
            ),
            (
                "value".to_string(),
                property_value_live_admin_arg(&assignment.value),
            ),
            (
                "display_value".to_string(),
                LivePoolAdminArg::String(assignment.value.to_string()),
            ),
            (
                "raw_value".to_string(),
                LivePoolAdminArg::String(assignment.raw_value.clone()),
            ),
            (
                "clear".to_string(),
                LivePoolAdminArg::Bool(assignment.clear),
            ),
        ]
        .into_iter()
        .collect(),
    )
}

fn property_value_json(value: &PropertyValue) -> serde_json::Value {
    match value {
        PropertyValue::None => serde_json::Value::Null,
        PropertyValue::U64(value) => serde_json::json!(value),
        PropertyValue::I64(value) => serde_json::json!(value),
        PropertyValue::String(value) => serde_json::json!(value),
        PropertyValue::Bool(value) => serde_json::json!(value),
        PropertyValue::EnumVariant(value) => serde_json::json!(value),
        PropertyValue::Bytes(value) => serde_json::json!(value),
        PropertyValue::Size(value) => serde_json::json!(value),
    }
}

fn property_value_live_admin_arg(value: &PropertyValue) -> LivePoolAdminArg {
    match value {
        PropertyValue::None => LivePoolAdminArg::Null,
        PropertyValue::U64(value) => LivePoolAdminArg::U64(*value),
        PropertyValue::I64(value) => LivePoolAdminArg::I64(*value),
        PropertyValue::String(value) => LivePoolAdminArg::String(value.clone()),
        PropertyValue::Bool(value) => LivePoolAdminArg::Bool(*value),
        PropertyValue::EnumVariant(value) => LivePoolAdminArg::U64(u64::from(*value)),
        PropertyValue::Bytes(value) => LivePoolAdminArg::Array(
            value
                .iter()
                .copied()
                .map(u64::from)
                .map(LivePoolAdminArg::U64)
                .collect(),
        ),
        PropertyValue::Size(value) => LivePoolAdminArg::U64(*value),
    }
}

fn normalized_assignment(assignment: &PropertyAssignment) -> String {
    if assignment.clear {
        format!("{}=-", assignment.key)
    } else {
        format!("{}={}", assignment.key, assignment.value)
    }
}

fn dataset_type_matches(dataset_type: DatasetType, filter: Option<DatasetTypeArg>) -> bool {
    filter
        .map(|filter| dataset_type == filter.to_dataset_type())
        .unwrap_or(true)
}

fn dataset_rows_from_catalog(
    pool: &str,
    catalog: &DatasetCatalog,
    filter: Option<DatasetTypeArg>,
    capacity: DatasetCapacityProjection,
) -> Vec<DatasetListRow> {
    catalog
        .list_all()
        .into_iter()
        .filter(|(_, _, dataset_type, _, _, _)| dataset_type_matches(*dataset_type, filter))
        .map(|(path, _, dataset_type, _, _, _)| DatasetListRow {
            pool: pool.to_string(),
            path,
            dataset_type,
            used_bytes: capacity.used_bytes,
            available_bytes: capacity.available_bytes,
            mountpoint: None,
        })
        .collect()
}

fn print_dataset_rows(pool: Option<&str>, rows: &[DatasetListRow], json: bool) {
    if json {
        print_json_or_exit(serde_json::json!({
            "ok": true,
            "pool": pool,
            "datasets": dataset_rows_json(rows),
        }));
        return;
    }

    println!(
        "{:<40} {:<12} {:>14} {:>14} {}",
        "NAME", "TYPE", "USED", "AVAILABLE", "MOUNTPOINT"
    );
    for row in rows {
        println!(
            "{:<40} {:<12} {:>14} {:>14} {}",
            format!("{}/{}", row.pool, row.path),
            row.dataset_type,
            optional_bytes(row.used_bytes),
            optional_bytes(row.available_bytes),
            row.mountpoint.as_deref().unwrap_or("-")
        );
    }
}

fn dataset_rows_json(rows: &[DatasetListRow]) -> Vec<serde_json::Value> {
    rows.iter()
        .map(|row| {
            serde_json::json!({
                "pool": row.pool.as_str(),
                "name": format!("{}/{}", row.pool, row.path),
                "path": row.path.as_str(),
                "type": row.dataset_type.to_string(),
                "used": row.used_bytes,
                "available": row.available_bytes,
                "mountpoint": row.mountpoint.as_deref(),
            })
        })
        .collect()
}

fn optional_bytes(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn bytes_from_blocks(blocks: u64, block_size: u32) -> u64 {
    blocks.saturating_mul(u64::from(block_size))
}

fn dataset_capacity_projection_from_statfs(stats: FileSystemStatfs) -> DatasetCapacityProjection {
    let used_blocks = stats.blocks.saturating_sub(stats.bfree);
    DatasetCapacityProjection {
        used_bytes: Some(bytes_from_blocks(used_blocks, stats.bsize)),
        available_bytes: Some(bytes_from_blocks(stats.bavail, stats.bsize)),
    }
}

fn list_pool_from_args(args: &DatasetListArgs) -> Option<String> {
    if let Some(pool) = args.pool.as_deref() {
        return Some(parse_pool_or_exit(pool, "list", args.json));
    }
    let devices = args
        .devices
        .as_deref()
        .filter(|devices| !devices.is_empty())?;
    let entries = match tidefs_pool_scan::scan_labels(devices) {
        Ok(entries) => entries,
        Err(err) => exit_dataset_error("list", format!("pool label scan failed: {err}"), args.json),
    };
    let config = match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config,
        Err(err) => exit_dataset_error("list", format!("pool assembly failed: {err}"), args.json),
    };
    Some(config.pool_name)
}

fn require_create_admission(
    catalog: &DatasetCatalog,
    path: &str,
    parent: &str,
) -> Result<(), String> {
    if !catalog.contains(parent) {
        return Err(format!(
            "parent dataset '{parent}' does not exist in the catalog"
        ));
    }
    if catalog.contains(path) {
        return Err(format!("dataset '{path}' already exists in the catalog"));
    }
    Ok(())
}

fn destroy_admission_from_catalog(
    catalog: &DatasetCatalog,
    path: &str,
    snapshot_count: usize,
    mounted_dataset_id: [u8; 16],
) -> Result<DestroyAdmission, String> {
    let children = catalog
        .list_children(path)
        .map_err(|err| format!("catalog error listing children of '{path}': {err}"))?;
    let live_mount = catalog
        .lookup(path)
        .map(|dataset_id| *dataset_id.as_bytes() == mounted_dataset_id)
        .unwrap_or(false);
    Ok(DestroyAdmission {
        child_count: children.len(),
        snapshot_count,
        live_mount,
    })
}

fn require_destroy_admission(
    path: &str,
    admission: &DestroyAdmission,
    force: bool,
) -> Result<(), String> {
    if !admission.has_hazards() || force {
        return Ok(());
    }
    Err(format!(
        "dataset '{path}' has {}; retry with --force to destroy it",
        admission.hazards().join(", ")
    ))
}

fn destroy_catalog_subtree(catalog: &mut DatasetCatalog, path: &str) -> Result<usize, String> {
    let prefix = format!("{path}/");
    let mut descendants: Vec<String> = catalog
        .list_all()
        .into_iter()
        .map(|(entry_path, _, _, _, _, _)| entry_path)
        .filter(|entry_path| entry_path.starts_with(&prefix))
        .collect();
    descendants.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| right.cmp(left)));
    let mut destroyed = 0;
    for descendant in descendants {
        catalog
            .destroy(&descendant)
            .map_err(|err| format!("catalog error destroying '{descendant}': {err}"))?;
        destroyed += 1;
    }
    catalog
        .destroy(path)
        .map_err(|err| format!("catalog error destroying '{path}': {err}"))?;
    Ok(destroyed + 1)
}

fn handle_create(args: DatasetCreateArgs) {
    let _guard = super::authz::require_local_only("dataset create");

    let target = parse_target_or_exit(&args.target, "create", args.json);
    let devices_ref = args.devices.as_deref();
    let full_path = target.dataset.clone();
    let (parent, leaf) = create_parent_and_leaf(&full_path);
    let sync_guarantee = parse_sync_or_exit(&args.sync, "create", args.json);
    let properties = parse_property_assignments_or_exit(&args.properties, "create", args.json);
    let features = parse_feature_names_or_exit(&args.features, "create", args.json);
    let dataset_type = args.dataset_type.to_dataset_type();
    let mountpoint = args
        .mountpoint
        .as_ref()
        .map(|path| path.display().to_string());

    if full_path == "root" {
        exit_dataset_error(
            "create",
            "'root' dataset cannot be re-created; it is created automatically with the pool",
            args.json,
        );
    }

    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "create");
        let devs = require_devices_for_cluster(devices_ref.map(|d| d), "create");
        let pool_guid = resolve_cluster_pool_guid(devs, "create");

        let dataset_id = dataset_id_from_name(&full_path);
        let delta = CatalogDelta::Create {
            path: full_path.clone(),
            dataset_id_bytes: dataset_id.as_bytes().to_vec(),
            dataset_type_u8: dataset_type.to_u8(),
            creation_txg: 1,
            properties: property_set_from_assignments(&properties).to_key_value_blob(),
            flags_u16: DatasetFlags::default_create().bits(),
        };

        let catalog_version = submit_cluster_delta(node_addr, node_id, pool_guid, &delta, "create");

        if args.json {
            print_json_or_exit(serde_json::json!({
                "ok": true,
                "operation": "create",
                "pool": target.pool,
                "dataset": full_path,
                "id": dataset_id.to_string(),
                "type": dataset_type.to_string(),
                "parent": parent,
                "mountpoint": mountpoint,
                "properties": property_assignments_json(&properties),
                "features": features,
                "catalog_version": catalog_version,
            }));
        } else {
            println!(
                "dataset '{full_path}' created in clustered pool '{}' (catalog_version={catalog_version})",
                target.pool
            );
            println!("  id={}  parent='{parent}'", format_dataset_id(&dataset_id));
        }
        return;
    }

    let mut fs = open_filesystem_with_live_args(
        &target.pool,
        devices_ref,
        "create",
        RecoveryPolicy::default(),
        args.json,
        super::live_owner::live_admin_args([
            ("target", LivePoolAdminArg::String(args.target.clone())),
            ("name", LivePoolAdminArg::String(leaf.to_string())),
            ("parent", LivePoolAdminArg::String(parent.clone())),
            (
                "type",
                LivePoolAdminArg::String(args.dataset_type.label().to_string()),
            ),
            (
                "mountpoint",
                super::live_owner::live_admin_optional_string(
                    mountpoint.as_ref().map(|path| path.to_string()),
                ),
            ),
            (
                "properties",
                LivePoolAdminArg::Array(property_assignments_live_admin_args(&properties)),
            ),
            (
                "features",
                LivePoolAdminArg::Array(
                    features
                        .iter()
                        .cloned()
                        .map(LivePoolAdminArg::String)
                        .collect(),
                ),
            ),
            ("sync", LivePoolAdminArg::String(args.sync.clone())),
        ]),
    );

    if let Err(err) = require_create_admission(fs.dataset_catalog(), &full_path, &parent) {
        exit_dataset_error("create", err, args.json);
    }

    let dataset_id = dataset_id_from_name(&full_path);
    let property_set = property_set_from_assignments(&properties);

    if let Err(err) = fs.dataset_catalog_mut().create(
        &full_path,
        dataset_id,
        dataset_type,
        1,
        property_set.to_key_value_blob(),
        DatasetFlags::default_create(),
        sync_guarantee,
    ) {
        exit_dataset_error(
            "create",
            format!("catalog error creating '{full_path}': {err}"),
            args.json,
        );
    }

    if let Err(err) = fs.persist_dataset_catalog() {
        exit_dataset_error(
            "create",
            format!("failed to persist catalog: {err}"),
            args.json,
        );
    }

    if args.json {
        print_json_or_exit(serde_json::json!({
            "ok": true,
            "operation": "create",
            "pool": target.pool,
            "dataset": full_path,
            "id": dataset_id.to_string(),
            "type": dataset_type.to_string(),
            "parent": parent,
            "mountpoint": mountpoint,
            "properties": property_assignments_json(&properties),
            "features": features,
        }));
    } else {
        println!("dataset '{full_path}' created in pool '{}'", target.pool);
        println!("  id={}  parent='{parent}'", format_dataset_id(&dataset_id));
    }
}
fn handle_list(args: DatasetListArgs) {
    let pool = list_pool_from_args(&args);

    // ── Cluster-authoritative path ─────────────────────────────────
    if args.cluster {
        let (node_addr, node_id) =
            validate_cluster_args(&args.cluster_node_addr, args.cluster_node_id, "list");
        let devs = require_devices_for_cluster(args.devices.as_deref(), "list");
        let pool_guid = resolve_cluster_pool_guid(devs, "list");
        let pool_name = pool.unwrap_or_else(|| "<devices>".to_string());

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
                let mut rows: Vec<_> = resp
                    .entries
                    .iter()
                    .filter_map(|entry| {
                        let dataset_type = DatasetType::from_u8(entry.dataset_type_u8)?;
                        if !dataset_type_matches(dataset_type, args.dataset_type) {
                            return None;
                        }
                        Some(DatasetListRow {
                            pool: pool_name.clone(),
                            path: entry.path.clone(),
                            dataset_type,
                            used_bytes: None,
                            available_bytes: None,
                            mountpoint: None,
                        })
                    })
                    .collect();
                rows.sort_by(|left, right| left.path.cmp(&right.path));
                if args.json {
                    let mut out = serde_json::json!({
                        "ok": true,
                        "pool": pool_name,
                        "catalog_version": resp.catalog_version,
                        "datasets": [],
                    });
                    out["datasets"] = serde_json::Value::Array(dataset_rows_json(&rows));
                    print_json_or_exit(out);
                } else {
                    print_dataset_rows(Some(&pool_name), &rows, false);
                }
                return;
            }
            Err(e) => {
                eprintln!("tidefsctl dataset list: cluster transport error: {e}");
                process::exit(1);
            }
        }
    }

    let Some(pool) = pool else {
        print_dataset_rows(None, &[], args.json);
        return;
    };

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &pool,
        devices_ref,
        "list",
        RecoveryPolicy::ReadOnly,
        args.json,
        super::live_owner::live_admin_args([(
            "type",
            super::live_owner::live_admin_optional_string(
                args.dataset_type
                    .map(|dataset_type| dataset_type.label().to_string()),
            ),
        )]),
    );
    let capacity = match fs.statfs() {
        Ok(stats) => dataset_capacity_projection_from_statfs(stats),
        Err(_) => DatasetCapacityProjection::default(),
    };
    let catalog = fs.dataset_catalog();
    let rows = dataset_rows_from_catalog(&pool, catalog, args.dataset_type, capacity);
    print_dataset_rows(Some(&pool), &rows, args.json);
}
fn handle_rename(args: DatasetRenameArgs) {
    let _guard = super::authz::require_local_only("dataset rename");

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
        false,
        super::live_owner::live_admin_args([
            ("old_name", LivePoolAdminArg::String(args.old_name.clone())),
            ("new_name", LivePoolAdminArg::String(args.new_name.clone())),
        ]),
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
    let mutates = !args.enable.is_empty() || !args.disable.is_empty();
    let _guard = super::authz::require_local_only_when_mutating("dataset set-strategy", mutates);

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        devices_ref,
        "set-strategy",
        RecoveryPolicy::default(),
        false,
        super::live_owner::live_admin_args([
            ("name", LivePoolAdminArg::String(args.name.clone())),
            (
                "enable",
                LivePoolAdminArg::Array(
                    args.enable
                        .iter()
                        .cloned()
                        .map(LivePoolAdminArg::String)
                        .collect(),
                ),
            ),
            (
                "disable",
                LivePoolAdminArg::Array(
                    args.disable
                        .iter()
                        .cloned()
                        .map(LivePoolAdminArg::String)
                        .collect(),
                ),
            ),
            ("list", LivePoolAdminArg::Bool(args.list)),
            (
                "class",
                super::live_owner::live_admin_optional_string(Some(args.class.clone())),
            ),
        ]),
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
    let _guard = super::authz::require_local_only("dataset upgrade");

    use tidefs_dataset_feature_flags::SupportedFeaturesV1;
    use tidefs_types_dataset_feature_flags_core::get_feature_class;

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &args.pool,
        devices_ref,
        "upgrade",
        RecoveryPolicy::default(),
        false,
        super::live_owner::live_admin_args([("name", LivePoolAdminArg::String(args.name.clone()))]),
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

    let mut pending = to_enable;
    while !pending.is_empty() {
        let mut deferred = Vec::new();
        let mut made_progress = false;

        for name in pending {
            if fs.feature_flags().is_enabled(&name) {
                continue;
            }
            let class = match get_feature_class(&name) {
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
                    made_progress = true;
                }
                Err(tidefs_dataset_feature_flags::FeatureFlagsError::MissingPrerequisite {
                    ..
                }) => deferred.push(name),
                Err(e) => {
                    let msg = format!("{e}");
                    eprintln!("  FAILED {name} ({class}) : {msg}");
                    failed.push((name.to_string(), msg));
                }
            }
        }

        if deferred.is_empty() {
            break;
        }
        if !made_progress {
            for name in deferred {
                let Some(class) = get_feature_class(&name) else {
                    skipped_count += 1;
                    continue;
                };
                if let Err(e) = fs
                    .feature_flags_mut()
                    .enable_feature_with_prereqs(name.clone(), class)
                {
                    let msg = format!("{e}");
                    eprintln!("  FAILED {name} ({class}) : {msg}");
                    failed.push((name.to_string(), msg));
                }
            }
            break;
        }
        pending = deferred;
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
    let target = parse_target_or_exit(&args.target, "get", args.json);
    let property = parse_property_key_or_exit(&args.property, "get", args.json);
    let fs = open_filesystem_with_live_args(
        &target.pool,
        args.devices.as_deref(),
        "get",
        RecoveryPolicy::ReadOnly,
        args.json,
        super::live_owner::live_admin_args([
            ("target", LivePoolAdminArg::String(args.target.clone())),
            ("name", LivePoolAdminArg::String(target.dataset.clone())),
            ("property", LivePoolAdminArg::String(property.to_string())),
        ]),
    );

    let path = target.dataset.as_str();
    // Resolve properties with full parent-chain inheritance.
    let effective = match fs.dataset_catalog().get_properties_with_inheritance(&path) {
        Ok(props) => props,
        Err(e) => {
            exit_dataset_error(
                "get",
                format!("cannot read properties for '{}': {e}", target.dataset),
                args.json,
            );
        }
    };

    let key = PropertyKey::new(&property);

    // Show the effective value with source.
    match effective.get(&key) {
        Some(entry) => {
            if args.json {
                print_json_or_exit(serde_json::json!({
                    "ok": true,
                    "operation": "get",
                    "pool": target.pool,
                    "dataset": target.dataset,
                    "property": property,
                    "value": property_value_json(&entry.value),
                    "display_value": entry.value.to_string(),
                    "source": entry.source.to_string(),
                }));
            } else {
                println!("property:  {property}");
                println!("value:     {}", entry.value);
                println!("source:    {}", entry.source);
            }
        }
        None => {
            exit_dataset_error(
                "get",
                format!("internal error resolving '{property}'"),
                args.json,
            );
        }
    }
}
fn handle_set(args: DatasetSetArgs) {
    let _guard = super::authz::require_local_only("dataset set");

    let target = parse_target_or_exit(&args.target, "set", args.json);
    let assignment = parse_property_assignment_or_exit(&args.assignment, "set", args.json);
    let live_assignment = normalized_assignment(&assignment);
    let mut fs = open_filesystem_with_live_args(
        &target.pool,
        args.devices.as_deref(),
        "set",
        RecoveryPolicy::ReplayOnly,
        args.json,
        super::live_owner::live_admin_args([
            ("target", LivePoolAdminArg::String(args.target.clone())),
            ("name", LivePoolAdminArg::String(target.dataset.clone())),
            (
                "property",
                LivePoolAdminArg::String(assignment.key.to_string()),
            ),
            ("assignment", LivePoolAdminArg::String(live_assignment)),
            ("value", property_value_live_admin_arg(&assignment.value)),
            (
                "display_value",
                LivePoolAdminArg::String(assignment.value.to_string()),
            ),
            ("clear", LivePoolAdminArg::Bool(assignment.clear)),
        ]),
    );

    let registry = tidefs_dataset_properties::build_registry();
    let key = PropertyKey::new(&assignment.key);

    let def = match tidefs_dataset_properties::lookup_property(&registry, &key) {
        Some(def) => def,
        None => exit_dataset_error(
            "set",
            format!("unsupported dataset property key: {}", assignment.key),
            args.json,
        ),
    };

    // Validate the proposed value against the registry.
    let path = target.dataset.as_str();
    let existing_props = fs
        .dataset_catalog()
        .get_properties(&path)
        .unwrap_or_default();

    if let Err(verr) =
        tidefs_dataset_properties::validate_set(&key, &assignment.value, def, &existing_props)
    {
        exit_dataset_error("set", format!("validation failed: {verr}"), args.json);
    }

    // Apply the change: clear or set.
    let mut props = existing_props;
    if assignment.clear {
        props.remove_local_override(&key);
    } else {
        props.set_local(key.clone(), assignment.value.clone());
    }

    match fs.dataset_catalog_mut().set_properties(&path, &props) {
        Ok(()) => {
            if let Err(e) = fs.persist_dataset_catalog() {
                exit_dataset_error(
                    "set",
                    format!("property set but catalog persist failed: {e}"),
                    args.json,
                );
            }
            if args.json {
                print_json_or_exit(serde_json::json!({
                    "ok": true,
                    "operation": "set",
                    "pool": target.pool,
                    "dataset": target.dataset,
                    "property": assignment.key,
                    "value": property_value_json(&assignment.value),
                    "display_value": assignment.value.to_string(),
                    "clear": assignment.clear,
                }));
            } else if assignment.clear {
                println!("cleared '{}' (now using default/inherited value)", key);
            } else {
                println!("{} = {}", key, assignment.value);
            }
        }
        Err(e) => {
            exit_dataset_error(
                "set",
                format!("cannot write properties for '{}': {e}", target.dataset),
                args.json,
            );
        }
    }
}

fn handle_list_props(args: DatasetListPropsArgs) {
    let fs = open_filesystem_with_live_args(
        &args.pool,
        args.devices.as_deref(),
        "list-props",
        RecoveryPolicy::ReadOnly,
        false,
        super::live_owner::live_admin_args([
            ("name", LivePoolAdminArg::String(args.name.clone())),
            (
                "family",
                super::live_owner::live_admin_optional_string(args.family.clone()),
            ),
        ]),
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
    let _guard = super::authz::require_local_only("dataset destroy");

    let target = parse_target_or_exit(&args.target, "destroy", args.json);
    let name = target.dataset.clone();

    if name == "root" {
        exit_dataset_error("destroy", "'root' dataset cannot be destroyed", args.json);
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

        if args.json {
            print_json_or_exit(serde_json::json!({
                "ok": true,
                "operation": "destroy",
                "pool": target.pool,
                "dataset": name,
                "force": args.force,
                "catalog_version": catalog_version,
            }));
        } else {
            println!(
                "dataset '{name}' destroyed in clustered pool '{}' (catalog_version={catalog_version})",
                target.pool
            );
        }
        return;
    }

    let devices_ref = args.devices.as_deref();
    let mut fs = open_filesystem_with_live_args(
        &target.pool,
        devices_ref,
        "destroy",
        RecoveryPolicy::default(),
        args.json,
        super::live_owner::live_admin_args([
            ("target", LivePoolAdminArg::String(args.target.clone())),
            ("name", LivePoolAdminArg::String(name.clone())),
            ("force", LivePoolAdminArg::Bool(args.force)),
        ]),
    );

    // Check dataset exists
    if !fs.dataset_catalog().contains(&name) {
        exit_dataset_error(
            "destroy",
            format!("dataset '{name}' does not exist in the catalog"),
            args.json,
        );
    }

    let admission = destroy_admission_from_catalog(
        fs.dataset_catalog(),
        &name,
        fs.list_snapshots().len(),
        fs.mounted_dataset_id(),
    )
    .unwrap_or_else(|err| exit_dataset_error("destroy", err, args.json));
    if let Err(err) = require_destroy_admission(&name, &admission, args.force) {
        exit_dataset_error("destroy", err, args.json);
    }

    let destroyed_entries = destroy_catalog_subtree(fs.dataset_catalog_mut(), &name)
        .unwrap_or_else(|err| exit_dataset_error("destroy", err, args.json));

    if let Err(err) = fs.persist_dataset_catalog() {
        exit_dataset_error(
            "destroy",
            format!("failed to persist catalog: {err}"),
            args.json,
        );
    }

    if args.json {
        print_json_or_exit(serde_json::json!({
            "ok": true,
            "operation": "destroy",
            "pool": target.pool,
            "dataset": name,
            "force": args.force,
            "destroyed_entries": destroyed_entries,
            "admission": {
                "children": admission.child_count,
                "snapshots": admission.snapshot_count,
                "live_mount": admission.live_mount,
            },
        }));
    } else {
        println!("dataset '{name}' destroyed");
    }
}

/// Format a DatasetId for compact CLI display (first 8 hex chars of UUID).
fn format_dataset_id(id: &DatasetId) -> String {
    id.to_string().chars().take(8).collect()
}

// ── seal-key handler ─────────────────────────────────────────────────

fn handle_seal_key(args: DatasetSealKeyArgs) {
    let _guard = super::authz::require_local_only("dataset seal-key");

    use tidefs_encryption::key_hierarchy::{DatasetDEK, PoolWrappingKey};
    use tidefs_encryption::key_manager::{KeyManager, KeyStore};
    use tidefs_local_object_store::StoreOptions;

    let live_args = super::live_owner::live_admin_args([
        (
            "name",
            tidefs_vfs_engine::LivePoolAdminArg::String(args.name.clone()),
        ),
        (
            "passphrase",
            tidefs_vfs_engine::LivePoolAdminArg::String(args.passphrase.clone()),
        ),
    ]);
    let devices_ref = args.devices.as_deref();
    let pool_path =
        resolve_pool_path_with_live_args(&args.pool, devices_ref, "seal-key", live_args);

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
    let _guard = super::authz::require_local_only("dataset rotate-key");

    use tidefs_encryption::key_hierarchy::PoolWrappingKey;
    use tidefs_encryption::key_manager::{KeyRotation, KeyStore};
    use tidefs_local_object_store::StoreOptions;

    let live_args = super::live_owner::live_admin_args([
        (
            "old_passphrase",
            tidefs_vfs_engine::LivePoolAdminArg::String(args.old_passphrase.clone()),
        ),
        (
            "old_salt",
            tidefs_vfs_engine::LivePoolAdminArg::String(args.old_salt.clone()),
        ),
        (
            "new_passphrase",
            tidefs_vfs_engine::LivePoolAdminArg::String(args.new_passphrase.clone()),
        ),
    ]);
    let devices_ref = args.devices.as_deref();
    let pool_path =
        resolve_pool_path_with_live_args(&args.pool, devices_ref, "rotate-key", live_args);

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
fn resolve_pool_path_with_live_args(
    pool: &str,
    devices: Option<&[PathBuf]>,
    operation: &str,
    live_args: LivePoolAdminArgs,
) -> PathBuf {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let config = scan_device_pool_config(pool, devs, operation);
        super::live_owner::route_or_refuse_active_for_uuid_with_args(
            "dataset",
            operation,
            pool,
            config.pool_uuid,
            config.state == tidefs_types_pool_label_core::PoolState::Active,
            live_args,
        );

        return super::offline_pool::metadata_dir("dataset", operation, &config.pool_uuid);
    }

    super::live_owner::route_with_args("dataset", operation, pool, live_args)
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
mod dataset_lifecycle_command_tests {
    use super::*;

    fn create_entry(catalog: &mut DatasetCatalog, path: &str, dataset_type: DatasetType) {
        catalog
            .create(
                path,
                dataset_id_from_name(path),
                dataset_type,
                1,
                PropertySet::new().to_key_value_blob(),
                DatasetFlags::default_create(),
                SyncGuarantee::Local,
            )
            .unwrap();
    }

    fn catalog_with(paths: &[(&str, DatasetType)]) -> DatasetCatalog {
        let mut catalog = DatasetCatalog::new();
        create_entry(&mut catalog, "root", DatasetType::Filesystem);
        for (path, dataset_type) in paths {
            create_entry(&mut catalog, path, *dataset_type);
        }
        catalog
    }

    #[test]
    fn create_admission_accepts_new_dataset_and_rejects_duplicate() {
        let catalog = catalog_with(&[("data", DatasetType::Filesystem)]);

        assert!(require_create_admission(&catalog, "logs", "root").is_ok());
        let duplicate = require_create_admission(&catalog, "data", "root").unwrap_err();
        assert!(duplicate.contains("already exists"));
    }

    #[test]
    fn create_admission_rejects_missing_parent() {
        let catalog = catalog_with(&[]);

        let err = require_create_admission(&catalog, "missing/child", "missing").unwrap_err();
        assert!(err.contains("parent dataset 'missing'"));
    }

    #[test]
    fn list_rows_filter_by_type_and_keep_json_columns() {
        let catalog = catalog_with(&[
            ("data", DatasetType::Filesystem),
            ("vol", DatasetType::Volume),
        ]);

        let rows = dataset_rows_from_catalog(
            "tank",
            &catalog,
            Some(DatasetTypeArg::Volume),
            DatasetCapacityProjection {
                used_bytes: Some(8192),
                available_bytes: Some(4096),
            },
        );
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].path, "vol");

        let json = dataset_rows_json(&rows);
        assert_eq!(json[0]["pool"], "tank");
        assert_eq!(json[0]["name"], "tank/vol");
        assert_eq!(json[0]["type"], "volume");
        assert_eq!(json[0]["used"], serde_json::json!(8192));
        assert_eq!(json[0]["available"], serde_json::json!(4096));
        assert_eq!(json[0]["mountpoint"], serde_json::Value::Null);
    }

    #[test]
    fn capacity_projection_reports_used_and_available_from_statfs() {
        let stats = FileSystemStatfs {
            blocks: 10,
            bfree: 6,
            bavail: 5,
            files: 0,
            ffree: 0,
            bsize: 4096,
            namelen: 0,
            frsize: 4096,
            fsid_hi: 0,
            fsid_lo: 0,
        };

        let capacity = dataset_capacity_projection_from_statfs(stats);
        assert_eq!(capacity.used_bytes, Some(16_384));
        assert_eq!(capacity.available_bytes, Some(20_480));
    }

    #[test]
    fn destroy_admission_requires_force_for_children_snapshots_or_live_mount() {
        let catalog = catalog_with(&[
            ("data", DatasetType::Filesystem),
            ("data/child", DatasetType::Filesystem),
        ]);
        let mounted_dataset_id = *dataset_id_from_name("data").as_bytes();

        let admission =
            destroy_admission_from_catalog(&catalog, "data", 1, mounted_dataset_id).unwrap();
        assert!(admission.has_hazards());
        let err = require_destroy_admission("data", &admission, false).unwrap_err();
        assert!(err.contains("--force"));
        assert!(require_destroy_admission("data", &admission, true).is_ok());
    }

    #[test]
    fn forced_destroy_removes_descendants_before_parent() {
        let mut catalog = catalog_with(&[
            ("data", DatasetType::Filesystem),
            ("data/child", DatasetType::Filesystem),
            ("data/child/grand", DatasetType::Filesystem),
        ]);

        let destroyed = destroy_catalog_subtree(&mut catalog, "data").unwrap();
        assert_eq!(destroyed, 3);
        assert!(!catalog.contains("data"));
        assert!(!catalog.contains("data/child"));
        assert!(catalog.contains("root"));
    }

    #[test]
    fn property_assignment_parser_covers_set_get_admission() {
        let assignment = parse_property_assignment_or_exit("layout.recordsize=128K", "set", true);
        assert_eq!(assignment.key, "layout.recordsize");
        assert_eq!(assignment.value, PropertyValue::Size(131_072));

        assert!(parser::parse_property_key("access.readonly").is_ok());
        assert!(parser::parse_property_key("unknown.property").is_err());
    }
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
