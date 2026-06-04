//! Snapshot subcommands.
//!
//! Wires CLI arguments to `tidefs_local_filesystem::LocalFileSystem` to
//! create, list, destroy, send, and receive point-in-time snapshot state.

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use tidefs_local_filesystem::{
    ChangedRecordExport, LocalFileSystem, LocalFileSystemOpenConfig, LocalStorageAllocatorPolicy,
    RecoveryPolicy, RootAuthenticationKey, SnapshotSummary,
};
use tidefs_local_object_store::StoreOptions;
use tidefs_transport::{NodeInfo, SessionCloseReason, Transport};

// ---------------------------------------------------------------------------
// Snapshot network transfer protocol (simple VFSSEND1 push/pull via VSNP)
// ---------------------------------------------------------------------------

const SNAP_NET_MAGIC: &[u8; 4] = b"VSNP";
const SNAP_KIND_ERROR: u8 = 0;
const SNAP_KIND_PUSH: u8 = 1;
const SNAP_KIND_PULL_REQUEST: u8 = 2;
const SNAP_KIND_PULL_RESPONSE: u8 = 3;
pub(crate) const SNAP_KIND_ACK: u8 = 4;
pub(crate) const SNAP_KIND_BLOCK_PUSH: u8 = 5;
pub(crate) const SNAP_KIND_BLOCK_PULL_REQUEST: u8 = 6;
pub(crate) const SNAP_KIND_BLOCK_PULL_RESPONSE: u8 = 7;

pub(crate) fn build_push_message(export: &[u8], auth_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + 4 + 32 + 4 + export.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_PUSH);
    msg.extend_from_slice(&32u32.to_le_bytes());
    msg.extend_from_slice(auth_key);
    msg.extend_from_slice(&(export.len() as u32).to_le_bytes());
    msg.extend_from_slice(export);
    msg
}

pub(crate) fn build_pull_request(auth_key: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + 4 + 32);
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_PULL_REQUEST);
    msg.extend_from_slice(&32u32.to_le_bytes());
    msg.extend_from_slice(auth_key);
    msg
}

#[allow(dead_code)]
pub(crate) fn build_ack(message: &str) -> Vec<u8> {
    let b = message.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + b.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_ACK);
    msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
    msg.extend_from_slice(b);
    msg
}

#[allow(dead_code)]

pub(crate) fn build_block_push_message(
    block_data: &[u8],
    device_name: &str,
    auth_key: &[u8; 32],
) -> Vec<u8> {
    let name_bytes = device_name.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + 32 + 4 + name_bytes.len() + 4 + block_data.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_BLOCK_PUSH);
    msg.extend_from_slice(&32u32.to_le_bytes());
    msg.extend_from_slice(auth_key);
    msg.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    msg.extend_from_slice(name_bytes);
    msg.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
    msg.extend_from_slice(block_data);
    msg
}

pub(crate) fn build_block_pull_request(device_name: &str, auth_key: &[u8; 32]) -> Vec<u8> {
    let name_bytes = device_name.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + 32 + 4 + name_bytes.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_BLOCK_PULL_REQUEST);
    msg.extend_from_slice(&32u32.to_le_bytes());
    msg.extend_from_slice(auth_key);
    msg.extend_from_slice(&(name_bytes.len() as u32).to_le_bytes());
    msg.extend_from_slice(name_bytes);
    msg
}

#[allow(dead_code)]
pub(crate) fn build_block_pull_response(block_data: &[u8]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(4 + 1 + 4 + block_data.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_BLOCK_PULL_RESPONSE);
    msg.extend_from_slice(&(block_data.len() as u32).to_le_bytes());
    msg.extend_from_slice(block_data);
    msg
}

#[allow(dead_code)]
pub(crate) fn build_error(message: &str) -> Vec<u8> {
    let b = message.as_bytes();
    let mut msg = Vec::with_capacity(4 + 1 + 4 + b.len());
    msg.extend_from_slice(SNAP_NET_MAGIC);
    msg.push(SNAP_KIND_ERROR);
    msg.extend_from_slice(&(b.len() as u32).to_le_bytes());
    msg.extend_from_slice(b);
    msg
}

#[allow(dead_code)]
pub(crate) enum SnapNetMessage {
    Push { auth_key: [u8; 32], export: Vec<u8> },
    PullRequest { auth_key: [u8; 32] },
    PullResponse { export: Vec<u8> },
    Ack { message: String },
    Error { message: String },
}

pub(crate) fn parse_snap_net_message(data: &[u8]) -> Result<SnapNetMessage, String> {
    if data.len() < 9 {
        return Err("message too short for VSNP header".into());
    }
    if &data[0..4] != SNAP_NET_MAGIC {
        return Err(format!("bad magic: {:?}", &data[0..4]));
    }
    let kind = data[4];
    match kind {
        SNAP_KIND_PUSH => {
            if data.len() < 9 + 4 {
                return Err("push too short".into());
            }
            let key_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!("push: key_len={key_len}, want 32"));
            }
            if data.len() < 9 + 32 + 4 {
                return Err("push too short for key+export_len".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&data[9..9 + 32]);
            let export_len = u32::from_le_bytes(data[9 + 32..13 + 32].try_into().unwrap()) as usize;
            let start = 13 + 32;
            if data.len() < start + export_len {
                return Err(format!(
                    "push: need {} bytes, got {}",
                    start + export_len,
                    data.len()
                ));
            }
            Ok(SnapNetMessage::Push {
                auth_key,
                export: data[start..start + export_len].to_vec(),
            })
        }
        SNAP_KIND_PULL_REQUEST => {
            if data.len() < 9 + 4 {
                return Err("pull_request too short".into());
            }
            let key_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            if key_len != 32 {
                return Err(format!("pull_request: key_len={key_len}"));
            }
            if data.len() < 9 + 32 {
                return Err("pull_request too short for key".into());
            }
            let mut auth_key = [0u8; 32];
            auth_key.copy_from_slice(&data[9..9 + 32]);
            Ok(SnapNetMessage::PullRequest { auth_key })
        }
        SNAP_KIND_PULL_RESPONSE => {
            if data.len() < 9 + 4 {
                return Err("pull_response too short".into());
            }
            let export_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            let start = 9;
            if data.len() < start + export_len {
                return Err(format!("pull_response: need {} bytes", start + export_len));
            }
            Ok(SnapNetMessage::PullResponse {
                export: data[start..start + export_len].to_vec(),
            })
        }
        SNAP_KIND_BLOCK_PULL_RESPONSE => {
            if data.len() < 9 + 4 {
                return Err("block_pull_response too short".into());
            }
            let data_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            let start = 9;
            if data.len() < start + data_len {
                return Err(format!(
                    "block_pull_response: need {} bytes",
                    start + data_len
                ));
            }
            Ok(SnapNetMessage::PullResponse {
                export: data[start..start + data_len].to_vec(),
            })
        }
        _ => {
            if data.len() < 9 + 4 {
                return Err("response too short".into());
            }
            let msg_len = u32::from_le_bytes(data[5..9].try_into().unwrap()) as usize;
            let start = 9;
            if data.len() < start + msg_len {
                return Err("response too short for message".into());
            }
            let message = String::from_utf8_lossy(&data[start..start + msg_len]).into_owned();
            match kind {
                SNAP_KIND_ACK => Ok(SnapNetMessage::Ack { message }),
                SNAP_KIND_ERROR => Ok(SnapNetMessage::Error { message }),
                other => Err(format!("unknown VSNP kind: {other}")),
            }
        }
    }
}

pub(crate) fn transport_request(
    local_node_id: u64,
    remote_node_id: u64,
    remote_addr: SocketAddr,
    request: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let mut transport = Transport::new(local_node_id);
    transport.add_node(NodeInfo::new(
        remote_node_id,
        vec![tidefs_transport::TransportAddr::Tcp(remote_addr)],
        0,
    ));

    let session_id = transport
        .connect(remote_node_id)
        .map_err(|e| format!("connect to {remote_addr}: {e:?}"))?;

    transport
        .perform_handshake(session_id)
        .map_err(|e| format!("handshake: {e:?}"))?;

    if let Err(e) = transport.send_message(session_id, &request) {
        let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
        return Err(format!("send: {e:?}"));
    }

    let response = match transport.recv_message(session_id) {
        Ok(raw) => raw,
        Err(e) => {
            let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
            return Err(format!("recv: {e:?}"));
        }
    };

    let _ = transport.close_session(session_id, SessionCloseReason::LocalShutdown);
    Ok(response)
}

/// Sub-subcommands for `tidefsctl snapshot`.
#[derive(Subcommand, Debug)]
pub enum SnapshotCommand {
    /// Create a named snapshot of the current filesystem root
    Create(SnapshotCreateArgs),
    /// List snapshots stored in the backing filesystem
    List(SnapshotListArgs),
    /// Destroy a named snapshot, unpinning its object graph from GC
    Destroy(SnapshotDestroyArgs),
    /// Export a changed-record snapshot stream from the current filesystem root
    Send(SnapshotSendArgs),
    /// Receive a changed-record snapshot stream into an empty backing directory
    Receive(SnapshotReceiveArgs),
    /// Rollback the dataset to a named snapshot state
    Rollback(SnapshotRollbackArgs),
}

/// `snapshot create <name> (--backing-dir <path> | --pool <pool> [--devices <dev>...])`
#[derive(Args, Debug)]
pub struct SnapshotCreateArgs {
    /// Snapshot name to create
    pub name: String,

    /// Backing directory for the local object store
    #[arg(
        long = "backing-dir",
        short = 'b',
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for pool-backed snapshots
    #[arg(
        long = "pool",
        short = 'p',
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for the pool (import before snapshot catalog access)
    #[arg(short = 'd', long = "devices", num_args = 1.., requires = "pool")]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot list (--backing-dir <path> | --pool <pool> [--devices <dev>...])`
#[derive(Args, Debug)]
pub struct SnapshotListArgs {
    /// Backing directory for the local object store
    #[arg(
        long = "backing-dir",
        short = 'b',
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for pool-backed snapshots
    #[arg(
        long = "pool",
        short = 'p',
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for the pool (import before snapshot catalog access)
    #[arg(short = 'd', long = "devices", num_args = 1.., requires = "pool")]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot destroy <name> (--backing-dir <path> | --pool <pool> [--devices <dev>...])`
#[derive(Args, Debug)]
pub struct SnapshotDestroyArgs {
    /// Snapshot name to destroy
    pub name: String,

    /// Backing directory for the local object store
    #[arg(
        long = "backing-dir",
        short = 'b',
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for pool-backed snapshots
    #[arg(
        long = "pool",
        short = 'p',
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for the pool (import before snapshot catalog access)
    #[arg(short = 'd', long = "devices", num_args = 1.., requires = "pool")]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot send (--backing-dir <path> | --pool <pool> [--devices <dev>...]) --output <path>`
#[derive(Args, Debug)]
pub struct SnapshotSendArgs {
    /// Backing directory for the local object store
    #[arg(
        long = "backing-dir",
        short = 'b',
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for pool-backed snapshots
    #[arg(
        long = "pool",
        short = 'p',
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for the pool (import before snapshot stream export)
    #[arg(short = 'd', long = "devices", num_args = 1.., requires = "pool")]
    pub devices: Option<Vec<PathBuf>>,

    /// Output path for the encoded changed-record stream
    #[arg(long = "output", short = 'o')]
    pub output: Option<PathBuf>,

    /// Push the stream to a remote storage-node via transport.
    #[arg(
        long = "target-addr",
        requires = "node_id",
        requires = "server_node_id"
    )]
    pub target_addr: Option<SocketAddr>,

    #[arg(long = "node-id", requires = "target-addr")]
    pub node_id: Option<u64>,

    #[arg(long = "server-node-id", requires = "target-addr")]
    pub server_node_id: Option<u64>,

    /// Stream format: vfssend1 (default) or vfssend2.
    #[arg(long = "format", default_value = "vfssend1")]
    pub format: String,

    /// Send an incremental delta from the specified base root.
    /// The hex key encodes (tid: u64, gen: u64, csum: u64) = 48 hex chars = 24 bytes.
    #[arg(long = "incremental", conflicts_with = "full")]
    pub incremental: bool,

    /// Hex-encoded base root key for incremental send (48 hex chars = 24 bytes).
    #[arg(long = "from-root", requires = "incremental")]
    pub from_root: Option<String>,

    /// Pool id for VFSSEND2 stream header (32 hex chars = 16 bytes).
    #[arg(long = "pool-id")]
    pub pool_id: Option<String>,

    /// Dataset id for VFSSEND2 stream header (32 hex chars = 16 bytes).
    #[arg(long = "dataset-id")]
    pub dataset_id: Option<String>,
}

/// `snapshot receive --backing-dir <path> --input <path>`
#[derive(Args, Debug)]
pub struct SnapshotReceiveArgs {
    /// Empty target backing directory to publish the received filesystem into
    #[arg(long = "backing-dir", short = 'b')]
    pub backing_dir: PathBuf,

    /// Input path containing a changed-record stream from `snapshot send`
    #[arg(long = "input", short = 'i')]
    pub input: Option<PathBuf>,

    /// Pull a stream from a remote storage-node via transport.
    #[arg(
        long = "source-addr",
        requires = "node_id",
        requires = "server_node_id"
    )]
    pub source_addr: Option<SocketAddr>,

    #[arg(long = "node-id", requires = "source-addr")]
    pub node_id: Option<u64>,

    #[arg(long = "server-node-id", requires = "source-addr")]
    pub server_node_id: Option<u64>,
}

/// `snapshot rollback <name> (--backing-dir <path> | --pool <pool> [--devices <dev>...])`
#[derive(Args, Debug)]
pub struct SnapshotRollbackArgs {
    /// Snapshot name to rollback to
    pub name: String,

    /// Backing directory for the local object store
    #[arg(
        long = "backing-dir",
        short = 'b',
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for pool-backed snapshots
    #[arg(
        long = "pool",
        short = 'p',
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for the pool (import before rollback)
    #[arg(short = 'd', long = "devices", num_args = 1.., requires = "pool")]
    pub devices: Option<Vec<PathBuf>>,
}

/// Dispatch the snapshot subcommand.
pub fn handle_snapshot(cmd: SnapshotCommand) {
    match cmd {
        SnapshotCommand::Create(args) => handle_create(args),
        SnapshotCommand::List(args) => handle_list(args),
        SnapshotCommand::Destroy(args) => handle_destroy(args),
        SnapshotCommand::Send(args) => handle_send(args),
        SnapshotCommand::Receive(args) => handle_receive(args),
        SnapshotCommand::Rollback(args) => handle_rollback(args),
    }
}

fn open_filesystem(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
) -> LocalFileSystem {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let pool_name = pool.unwrap_or("<unnamed>");
        let lock_dir = std::env::temp_dir().join("tidefs-import");
        if let Err(err) = std::fs::create_dir_all(&lock_dir) {
            eprintln!(
                "tidefsctl snapshot {operation}: cannot create import lock dir {}: {err}",
                lock_dir.display()
            );
            process::exit(1);
        }

        let pool_uuid = match tidefs_pool_import::pool_import(devs, &lock_dir, false, None, None) {
            Ok(imported) => {
                eprintln!(
                    "tidefsctl snapshot {operation}: pool '{}' imported (uuid={}, devices={})",
                    pool_name,
                    hex_uuid(&imported.config.pool_uuid),
                    imported.config.device_count
                );
                imported.config.pool_uuid
            }
            Err(tidefs_pool_import::ImportError::AlreadyImported { pool_uuid }) => pool_uuid,
            Err(err) => {
                eprintln!(
                    "tidefsctl snapshot {operation}: pool import failed for '{pool_name}': {err}"
                );
                process::exit(1);
            }
        };

        let metadata_dir = PathBuf::from("/run/tidefs/pools").join(hex_uuid(&pool_uuid));
        if let Err(err) = std::fs::create_dir_all(&metadata_dir) {
            eprintln!(
                "tidefsctl snapshot {operation}: cannot create pool metadata dir {}: {err}",
                metadata_dir.display()
            );
            process::exit(1);
        }

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
                    "tidefsctl snapshot {operation}: failed to open block-device-backed pool '{pool_name}' at {}: {err}",
                    metadata_dir.display()
                );
                process::exit(1);
            }
        };
    }

    let path = match backing_dir {
        Some(path) => path.clone(),
        None => PathBuf::from(pool.unwrap_or_else(|| {
            eprintln!("tidefsctl snapshot {operation}: --backing-dir or --pool is required");
            process::exit(1);
        })),
    };

    match LocalFileSystem::open_with_allocator_policy_and_root_authentication_key(
        &path,
        LocalFileSystemOpenConfig {
            options: StoreOptions::default(),
            allocator_policy: LocalStorageAllocatorPolicy::default(),
            root_authentication_key: root_authentication_key(),
            encryption: None,
            compression: None,
            log_device_device_path: None,
            recovery_policy,
            block_devices: None,
        },
    ) {
        Ok(fs) => fs,
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot {operation}: failed to open filesystem at {}: {err}",
                path.display()
            );
            process::exit(1);
        }
    }
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn root_authentication_key() -> RootAuthenticationKey {
    RootAuthenticationKey::from_environment().unwrap_or_else(|_| RootAuthenticationKey::demo_key())
}

fn snapshot_summary_line(summary: &SnapshotSummary) -> String {
    format!(
        "snapshot '{}' (source tx={}, source gen={}, created gen={})",
        summary.name,
        summary.source_transaction_id,
        summary.source_generation,
        summary.created_at_generation
    )
}

#[allow(dead_code)]
fn send_export_summary(export: &ChangedRecordExport) -> String {
    format!(
        "changed-record stream v{} (roots={}, records={}, payload={} bytes, snapshots={})",
        export.stream_version,
        export.roots.len(),
        export.total_records,
        export.payload_bytes,
        export
            .roots
            .iter()
            .flat_map(|root| root.records.iter())
            .filter(|record| {
                matches!(
                    record.role,
                    tidefs_local_filesystem::ChangedRecordObjectRole::TransactionSnapshotCatalogEntry
                )
            })
            .count()
    )
}

fn hex_to_bytes(hex_str: &str) -> Result<Vec<u8>, String> {
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if hex.len() % 2 != 0 {
        return Err(format!(
            "hex string must have even length, got {}",
            hex.len()
        ));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

fn parse_hex_128(hex_str: &str) -> Result<[u8; 16], String> {
    let bytes = hex_to_bytes(hex_str)?;
    if bytes.len() != 16 {
        return Err(format!(
            "expected 32 hex chars (16 bytes), got {} hex chars",
            hex_str.len()
        ));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn snapshot_backing_path(backing_dir: Option<&PathBuf>, pool: Option<&str>) -> PathBuf {
    match backing_dir {
        Some(p) => p.clone(),
        None => PathBuf::from(pool.unwrap_or_else(|| {
            eprintln!("tidefsctl snapshot send: --backing-dir or --pool required");
            process::exit(1);
        })),
    }
}

fn parse_incremental_from_root(
    hex_key: &Option<String>,
    backing_path: &std::path::Path,
) -> Result<tidefs_local_filesystem::CommittedRootSummary, String> {
    let hex = hex_key
        .as_deref()
        .ok_or("--from-root required for incremental send")?;
    let key_bytes = hex_to_bytes(hex)?;
    if key_bytes.len() != 24 {
        return Err(format!(
            "--from-root must be 24 bytes (48 hex chars), got {}",
            key_bytes.len()
        ));
    }
    let tid = u64::from_le_bytes(key_bytes[0..8].try_into().unwrap());
    let gen = u64::from_le_bytes(key_bytes[8..16].try_into().unwrap());
    let csum = u64::from_le_bytes(key_bytes[16..24].try_into().unwrap());

    let audit = tidefs_local_filesystem::audit_recovery(backing_path, StoreOptions::default())
        .map_err(|e| format!("audit recovery: {e}"))?;

    audit
        .valid_committed_roots
        .iter()
        .find(|r| r.transaction_id == tid && r.generation == gen && r.superblock_checksum.0 == csum)
        .cloned()
        .ok_or_else(|| format!("from_root not found: tid={tid} gen={gen} csum={csum:#016x}"))
}

fn handle_create(args: SnapshotCreateArgs) {
    let snapshot_name = &args.name;
    let mut fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "create",
        RecoveryPolicy::default(),
    );

    match fs.create_snapshot(snapshot_name) {
        Ok(summary) => {
            println!("{} created", snapshot_summary_line(&summary));
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot create: failed to create snapshot '{snapshot_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_list(args: SnapshotListArgs) {
    let fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "list",
        RecoveryPolicy::ReadOnly,
    );
    let mut snapshots = fs.list_snapshots();
    snapshots.sort_by(|a, b| {
        a.created_at_generation
            .cmp(&b.created_at_generation)
            .then_with(|| a.name.cmp(&b.name))
    });

    if snapshots.is_empty() {
        println!("no snapshots");
        return;
    }

    for summary in snapshots {
        println!("{}", snapshot_summary_line(&summary));
    }
}

fn handle_destroy(args: SnapshotDestroyArgs) {
    let snapshot_name = &args.name;
    let mut fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "destroy",
        RecoveryPolicy::default(),
    );

    // delete_snapshot validates the entry is a Snapshot (not clone/bookmark),
    // checks holds, unpins the SnapshotCatalog root from the GC pin set via
    // the embedded DatasetLifecycle, and removes the metadata from the catalog.
    match fs.delete_snapshot(snapshot_name) {
        Ok(summary) => {
            println!("{} destroyed", snapshot_summary_line(&summary));
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot destroy: failed to destroy snapshot '{snapshot_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_rollback(args: SnapshotRollbackArgs) {
    let snapshot_name = &args.name;
    let mut fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "rollback",
        RecoveryPolicy::default(),
    );

    match fs.rollback_to_snapshot(snapshot_name) {
        Ok(report) => {
            println!(
                "rolled back to snapshot '{}' (generation {} -> {}, restored source gen {}, {} snapshot entries)",
                report.snapshot.name,
                report.generation_before,
                report.published_generation,
                report.restored_source_generation,
                report.snapshot_catalog_entries,
            );
            if report.production_fsck_required {
                eprintln!("note: fsck was required during rollback");
            }
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot rollback: failed to rollback to snapshot '{snapshot_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_send(args: SnapshotSendArgs) {
    let mut fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "send",
        RecoveryPolicy::default(),
    );

    // Export: VFSSEND2 path or VFSSEND1 path, full or incremental.
    let encoded = if args.format == "vfssend2" {
        let pool_id = parse_hex_128(
            args.pool_id
                .as_deref()
                .unwrap_or("00000000000000000000000000000000"),
        )
        .unwrap_or([0u8; 16]);
        let dataset_id = parse_hex_128(
            args.dataset_id
                .as_deref()
                .unwrap_or("00000000000000000000000000000000"),
        )
        .unwrap_or([0u8; 16]);

        if args.incremental {
            let path = snapshot_backing_path(args.backing_dir.as_ref(), args.pool.as_deref());
            let from_root = match parse_incremental_from_root(&args.from_root, &path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("tidefsctl snapshot send: {e}");
                    process::exit(1);
                }
            };
            match fs.export_incremental_vfssend2(pool_id, dataset_id, &from_root) {
                Ok(encoded) => encoded,
                Err(err) => {
                    eprintln!("tidefsctl snapshot send: VFSSEND2 incremental export failed: {err}");
                    process::exit(1);
                }
            }
        } else {
            match fs.export_vfssend2(pool_id, dataset_id) {
                Ok(encoded) => encoded,
                Err(err) => {
                    eprintln!("tidefsctl snapshot send: VFSSEND2 export failed: {err}");
                    process::exit(1);
                }
            }
        }
    } else if args.incremental {
        let from_root = {
            let path = snapshot_backing_path(args.backing_dir.as_ref(), args.pool.as_deref());
            match parse_incremental_from_root(&args.from_root, &path) {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("tidefsctl snapshot send: {e}");
                    process::exit(1);
                }
            }
        };
        match fs.export_incremental_changed_records(&from_root) {
            Ok(export) => export.encode(),
            Err(err) => {
                eprintln!("tidefsctl snapshot send: incremental export failed: {err}");
                process::exit(1);
            }
        }
    } else {
        match fs.export_changed_records() {
            Ok(export) => export.encode(),
            Err(err) => {
                eprintln!("tidefsctl snapshot send: failed to export changed records: {err}");
                process::exit(1);
            }
        }
    };

    // Network push: send the encoded export + auth key to a remote storage-node.
    if let Some(addr) = args.target_addr {
        let node_id = args.node_id.unwrap_or(1);
        let server_node_id = args.server_node_id.unwrap_or(2);
        let auth_key = root_authentication_key();
        let req = build_push_message(&encoded, &auth_key.as_bytes32());

        let response = match transport_request(node_id, server_node_id, addr, req) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("tidefsctl snapshot send: transport to {addr}: {e}");
                process::exit(1);
            }
        };

        match parse_snap_net_message(&response) {
            Ok(SnapNetMessage::Ack { message }) => {
                println!(
                    "pushed stream to {addr}: {message} ({} bytes, format={})",
                    encoded.len(),
                    args.format
                );
            }
            Ok(SnapNetMessage::Error { message }) => {
                eprintln!("tidefsctl snapshot send: remote error: {message}");
                process::exit(1);
            }
            _ => {
                eprintln!("tidefsctl snapshot send: bad response from {addr}");
                process::exit(1);
            }
        }

        // Also write to local file if --output was given.
        if let Some(output) = &args.output {
            if let Err(err) = fs::write(output, &encoded) {
                eprintln!(
                    "tidefsctl snapshot send: also wrote to {}: {err}",
                    output.display()
                );
            }
        }
        return;
    }

    // Local file output.
    let output = match &args.output {
        Some(p) => p.clone(),
        None => {
            eprintln!("tidefsctl snapshot send: --output or --target-addr required");
            process::exit(1);
        }
    };

    if let Err(err) = fs::write(&output, &encoded) {
        eprintln!(
            "tidefsctl snapshot send: failed to write stream to {}: {err}",
            output.display()
        );
        process::exit(1);
    }

    println!(
        "wrote stream to {} ({} bytes, format={})",
        output.display(),
        encoded.len(),
        args.format
    );
}

fn handle_receive(args: SnapshotReceiveArgs) {
    // Network pull: fetch stream from a remote storage-node.
    if let Some(addr) = args.source_addr {
        let node_id = args.node_id.unwrap_or(1);
        let server_node_id = args.server_node_id.unwrap_or(2);
        let auth_key = root_authentication_key();
        let req = build_pull_request(&auth_key.as_bytes32());

        let response = match transport_request(node_id, server_node_id, addr, req) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("tidefsctl snapshot receive: transport from {addr}: {e}");
                process::exit(1);
            }
        };

        let export_bytes = match parse_snap_net_message(&response) {
            Ok(SnapNetMessage::PullResponse { export }) => export,
            Ok(SnapNetMessage::Error { message }) => {
                eprintln!("tidefsctl snapshot receive: remote error: {message}");
                process::exit(1);
            }
            _ => {
                eprintln!("tidefsctl snapshot receive: bad response from {addr}");
                process::exit(1);
            }
        };

        let export =
            match tidefs_local_filesystem::vfssend2_bridge::decode_any_stream_to_changed_records(
                &export_bytes,
            ) {
                Ok(e) => e,
                Err(err) => {
                    eprintln!("tidefsctl snapshot receive: decode from {addr}: {err}");
                    process::exit(1);
                }
            };

        let report =
            match LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
                &args.backing_dir,
                StoreOptions::default(),
                &export,
                auth_key,
            ) {
                Ok(r) => r,
                Err(err) => {
                    eprintln!(
                        "tidefsctl snapshot receive: receive into {}: {err}",
                        args.backing_dir.display()
                    );
                    process::exit(1);
                }
            };

        println!(
            "pulled stream v{} from {addr} into {} (roots={}, records={}, payload={} bytes, snapshots={}, generation={}, tx={})",
            report.stream_version,
            args.backing_dir.display(),
            report.imported_roots,
            report.imported_records,
            report.imported_payload_bytes,
            report.snapshot_catalog_entries,
            report.selected_generation,
            report.selected_transaction_id,
        );

        // Also save to local file if --input was given.
        if let Some(input) = &args.input {
            if let Err(err) = fs::write(input, &export_bytes) {
                eprintln!(
                    "tidefsctl snapshot receive: also saved to {}: {err}",
                    input.display()
                );
            }
        }
        return;
    }

    // Local file input.
    let input = match &args.input {
        Some(p) => p.clone(),
        None => {
            eprintln!("tidefsctl snapshot receive: --input or --source-addr required");
            process::exit(1);
        }
    };

    let bytes = match fs::read(&input) {
        Ok(b) => b,
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot receive: failed to read {}: {err}",
                input.display()
            );
            process::exit(1);
        }
    };
    let export =
        match tidefs_local_filesystem::vfssend2_bridge::decode_any_stream_to_changed_records(&bytes)
        {
            Ok(e) => e,
            Err(err) => {
                eprintln!("tidefsctl snapshot receive: decode: {err}");
                process::exit(1);
            }
        };
    let report =
        match LocalFileSystem::receive_changed_records_into_empty_root_with_root_authentication_key(
            &args.backing_dir,
            StoreOptions::default(),
            &export,
            root_authentication_key(),
        ) {
            Ok(r) => r,
            Err(err) => {
                eprintln!(
                    "tidefsctl snapshot receive: receive into {}: {err}",
                    args.backing_dir.display()
                );
                process::exit(1);
            }
        };

    println!(
        "received stream v{} into {} (roots={}, records={}, payload={} bytes, snapshots={}, generation={}, tx={})",
        report.stream_version,
        args.backing_dir.display(),
        report.imported_roots,
        report.imported_records,
        report.imported_payload_bytes,
        report.snapshot_catalog_entries,
        report.selected_generation,
        report.selected_transaction_id,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_create_args_bindings() {
        let args = SnapshotCreateArgs {
            name: "before-upgrade".into(),
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            pool: None,
            devices: None,
        };
        assert_eq!(args.name, "before-upgrade");
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
    }

    #[test]
    fn snapshot_list_args_bindings() {
        let args = SnapshotListArgs {
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            pool: None,
            devices: None,
        };
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
    }

    #[test]
    fn snapshot_destroy_args_bindings() {
        let args = SnapshotDestroyArgs {
            name: "mysnap".into(),
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            pool: None,
            devices: None,
        };
        assert_eq!(args.name, "mysnap");
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
    }

    #[test]
    fn snapshot_create_pool_args_bindings() {
        let args = SnapshotCreateArgs {
            name: "before-upgrade".into(),
            backing_dir: None,
            pool: Some("mypool".into()),
            devices: Some(vec![PathBuf::from("/dev/sdb"), PathBuf::from("/dev/sdc")]),
        };
        assert_eq!(args.pool.as_deref(), Some("mypool"));
        assert_eq!(
            args.devices,
            Some(vec![PathBuf::from("/dev/sdb"), PathBuf::from("/dev/sdc")])
        );
    }

    #[test]
    fn snapshot_destroy_default_args() {
        let cmd = SnapshotCommand::Destroy(SnapshotDestroyArgs {
            name: "test".into(),
            backing_dir: Some(PathBuf::from("/backing")),
            pool: None,
            devices: None,
        });
        match cmd {
            SnapshotCommand::Destroy(args) => {
                assert_eq!(args.name, "test");
                assert_eq!(args.backing_dir, Some(PathBuf::from("/backing")));
            }
            SnapshotCommand::Create(_)
            | SnapshotCommand::List(_)
            | SnapshotCommand::Send(_)
            | SnapshotCommand::Receive(_)
            | SnapshotCommand::Rollback(_) => {
                panic!("expected destroy command")
            }
        }
    }

    #[test]
    fn snapshot_send_args_bindings() {
        let args = SnapshotSendArgs {
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            pool: None,
            devices: None,
            output: Some(PathBuf::from("/tmp/stream.vfssend1")),
            target_addr: None,
            node_id: None,
            server_node_id: None,
            format: "vfssend1".into(),
            incremental: false,
            from_root: None,
            pool_id: None,
            dataset_id: None,
        };
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
        assert_eq!(args.output, Some(PathBuf::from("/tmp/stream.vfssend1")));
        assert!(args.target_addr.is_none());
    }

    #[test]
    fn snapshot_receive_args_bindings() {
        let args = SnapshotReceiveArgs {
            backing_dir: PathBuf::from("/tmp/target"),
            input: Some(PathBuf::from("/tmp/stream.vfssend1")),
            source_addr: None,
            node_id: None,
            server_node_id: None,
        };
        assert_eq!(args.backing_dir, PathBuf::from("/tmp/target"));
        assert_eq!(args.input, Some(PathBuf::from("/tmp/stream.vfssend1")));
        assert!(args.source_addr.is_none());
    }
}
