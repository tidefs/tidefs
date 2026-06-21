// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
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
    ChangedRecordExport, HoldInfo, LocalFileSystem, LocalFileSystemOpenConfig,
    LocalStorageAllocatorPolicy, RecoveryPolicy, RootAuthenticationKey, SnapshotDescriptor,
    SnapshotKind, SnapshotRetentionPolicy, SnapshotRetentionReport, SnapshotSummary,
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
    /// Manage writable local snapshot clones
    Clone(SnapshotCloneArgs),
    /// Manage lightweight local snapshot bookmarks
    Bookmark(SnapshotBookmarkArgs),
    /// Place a deletion-prevention hold on a snapshot or clone
    Hold(SnapshotHoldArgs),
    /// Release a deletion-prevention hold from a snapshot or clone
    Release(SnapshotReleaseArgs),
    /// Inspect snapshot and clone holds
    Holds(SnapshotHoldsArgs),
    /// Prune regular local snapshots by retention policy
    Prune(SnapshotPruneArgs),
    /// Destroy a named snapshot, unpinning its object graph from GC
    Destroy(SnapshotDestroyArgs),
    /// Export a changed-record snapshot stream from the current filesystem root
    Send(SnapshotSendArgs),
    /// Receive a changed-record snapshot stream through the live pool owner
    Receive(SnapshotReceiveArgs),
    /// Rollback the dataset to a named snapshot state
    Rollback(SnapshotRollbackArgs),
    /// Register the runtime-pending read-only snapshot export mount surface
    Export(SnapshotExportArgs),
    /// Register the runtime-pending one-shot snapshot file extraction surface
    Extract(SnapshotExtractArgs),
}

/// `snapshot create <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotCreateArgs {
    /// Pool and snapshot name
    #[arg(value_name = "POOL_AND_SNAPSHOT", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported snapshot access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot list <pool> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotListArgs {
    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value,
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for imported-pool snapshots routed through the live owner
    #[arg(
        value_name = "POOL",
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for offline/not-yet-imported snapshot access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir",
        requires = "pool"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot clone <create|delete|promote> ...`
#[derive(Args, Debug)]
pub struct SnapshotCloneArgs {
    #[command(subcommand)]
    pub cmd: SnapshotCloneCommand,
}

/// Subcommands for `snapshot clone`.
#[derive(Subcommand, Debug)]
pub enum SnapshotCloneCommand {
    /// Create a writable clone from a source snapshot or clone
    Create(SnapshotCloneCreateArgs),
    /// Delete a clone through clone lifecycle authority
    Delete(SnapshotCloneDeleteArgs),
    /// Promote a clone to an independent regular snapshot
    Promote(SnapshotClonePromoteArgs),
}

/// `snapshot clone create <pool> <clone> <source> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotCloneCreateArgs {
    /// Pool, clone name, and source snapshot/clone name
    #[arg(
        value_name = "POOL_CLONE_SOURCE",
        num_args = 2..=3,
        required = true
    )]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported clone access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot clone delete <pool> <clone> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotCloneDeleteArgs {
    /// Pool and clone name
    #[arg(value_name = "POOL_AND_CLONE", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported clone access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot clone promote <pool> <clone> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotClonePromoteArgs {
    /// Pool and clone name
    #[arg(value_name = "POOL_AND_CLONE", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported clone access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot bookmark <create|delete> ...`
#[derive(Args, Debug)]
pub struct SnapshotBookmarkArgs {
    #[command(subcommand)]
    pub cmd: SnapshotBookmarkCommand,
}

/// Subcommands for `snapshot bookmark`.
#[derive(Subcommand, Debug)]
pub enum SnapshotBookmarkCommand {
    /// Create a lightweight bookmark from a source snapshot or clone
    Create(SnapshotBookmarkCreateArgs),
    /// Delete a bookmark through bookmark lifecycle authority
    Delete(SnapshotBookmarkDeleteArgs),
}

/// `snapshot bookmark create <pool> <bookmark> <source> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotBookmarkCreateArgs {
    /// Pool, bookmark name, and source snapshot/clone name
    #[arg(
        value_name = "POOL_BOOKMARK_SOURCE",
        num_args = 2..=3,
        required = true
    )]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported bookmark access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot bookmark delete <pool> <bookmark> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotBookmarkDeleteArgs {
    /// Pool and bookmark name
    #[arg(value_name = "POOL_AND_BOOKMARK", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported bookmark access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot hold <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotHoldArgs {
    /// Pool and snapshot/clone name
    #[arg(value_name = "POOL_AND_ENTRY", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported hold access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot release <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotReleaseArgs {
    /// Pool and snapshot/clone name
    #[arg(value_name = "POOL_AND_ENTRY", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported hold access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot holds <pool> [name] [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotHoldsArgs {
    /// Pool and optional snapshot/clone name
    #[arg(value_name = "POOL_AND_ENTRY", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported hold inspection
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot prune <pool> [--keep-latest <n>] [--max-age-generations <n>]`
#[derive(Args, Debug)]
pub struct SnapshotPruneArgs {
    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value,
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for imported-pool pruning routed through the live owner
    #[arg(
        value_name = "POOL",
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for offline/not-yet-imported prune access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir",
        requires = "pool"
    )]
    pub devices: Option<Vec<PathBuf>>,

    /// Keep at most this many newest regular snapshots
    #[arg(long = "keep-latest", value_name = "COUNT")]
    pub keep_latest: Option<usize>,

    /// Delete regular snapshots older than this many filesystem generations
    #[arg(long = "max-age-generations", value_name = "GENERATIONS")]
    pub max_age_generations: Option<u64>,
}

/// `snapshot destroy <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotDestroyArgs {
    /// Pool and snapshot name
    #[arg(value_name = "POOL_AND_SNAPSHOT", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported snapshot access
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot send <pool> [--devices <dev>...] --output <path>`
#[derive(Args, Debug)]
pub struct SnapshotSendArgs {
    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value,
        conflicts_with = "pool",
        required_unless_present = "pool"
    )]
    pub backing_dir: Option<PathBuf>,

    /// Pool name for imported-pool snapshots routed through the live owner
    #[arg(
        value_name = "POOL",
        conflicts_with = "backing_dir",
        required_unless_present = "backing_dir"
    )]
    pub pool: Option<String>,

    /// Block devices for offline/not-yet-imported snapshot stream export
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir",
        requires = "pool"
    )]
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

/// `snapshot receive <pool> --input <path>`
#[derive(Args, Debug)]
pub struct SnapshotReceiveArgs {
    /// Pool name for imported-pool snapshots routed through the live owner
    pub pool: String,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

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

    #[arg(long = "node-id", requires = "source_addr")]
    pub node_id: Option<u64>,

    #[arg(long = "server-node-id", requires = "source_addr")]
    pub server_node_id: Option<u64>,
}

/// `snapshot rollback <pool> <name> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotRollbackArgs {
    /// Pool and snapshot name
    #[arg(value_name = "POOL_AND_SNAPSHOT", num_args = 1..=2, required = true)]
    pub operands: Vec<String>,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported rollback
    #[arg(
        short = 'd',
        long = "devices",
        num_args = 1..,
        conflicts_with = "backing_dir"
    )]
    pub devices: Option<Vec<PathBuf>>,
}

/// `snapshot export <snapshot-name> <export-path>`
/// Parse arguments for the runtime-pending read-only snapshot export surface.
/// Snapshot names follow the `@` prefix convention, e.g. `mypool@mysnap`.
#[derive(Args, Debug)]
pub struct SnapshotExportArgs {
    /// Pool and snapshot name in pool@snapshot form
    #[arg(
        value_name = "SNAPSHOT_NAME",
        help = "Snapshot name in pool@snapshot form"
    )]
    pub snapshot_name: String,

    /// Mount path reserved for the future read-only FUSE export session
    #[arg(
        value_name = "EXPORT_PATH",
        help = "Filesystem path reserved for the future read-only snapshot view"
    )]
    pub export_path: PathBuf,
}

/// `snapshot extract <snapshot-name> <file-path>`
/// Parse arguments for the runtime-pending one-shot snapshot extraction surface.
/// Snapshot names follow the `@` prefix convention, e.g. `mypool@mysnap`.
#[derive(Args, Debug)]
pub struct SnapshotExtractArgs {
    /// Pool and snapshot name in pool@snapshot form
    #[arg(
        value_name = "SNAPSHOT_NAME",
        help = "Snapshot name in pool@snapshot form"
    )]
    pub snapshot_name: String,

    /// File path within the snapshot to extract
    #[arg(
        value_name = "FILE_PATH",
        help = "Path of the file within the snapshot to extract"
    )]
    pub file_path: String,

    /// Output file path; writes to stdout when omitted
    #[arg(
        long = "output",
        short = 'o',
        help = "Write extracted content to this file instead of stdout"
    )]
    pub output: Option<PathBuf>,
}

/// Dispatch the snapshot subcommand.
pub fn handle_snapshot(cmd: SnapshotCommand) {
    match cmd {
        SnapshotCommand::Create(args) => handle_create(args),
        SnapshotCommand::List(args) => handle_list(args),
        SnapshotCommand::Clone(args) => handle_clone(args.cmd),
        SnapshotCommand::Bookmark(args) => handle_bookmark(args.cmd),
        SnapshotCommand::Hold(args) => handle_hold(args),
        SnapshotCommand::Release(args) => handle_release(args),
        SnapshotCommand::Holds(args) => handle_holds(args),
        SnapshotCommand::Prune(args) => handle_prune(args),
        SnapshotCommand::Destroy(args) => handle_destroy(args),
        SnapshotCommand::Send(args) => handle_send(args),
        SnapshotCommand::Receive(args) => handle_receive(args),
        SnapshotCommand::Rollback(args) => handle_rollback(args),
        SnapshotCommand::Export(args) => handle_export(args),
        SnapshotCommand::Extract(args) => handle_extract(args),
    }
}

fn open_filesystem(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
) -> LocalFileSystem {
    open_filesystem_with_live_args(
        backing_dir,
        pool,
        devices,
        operation,
        recovery_policy,
        serde_json::Value::Null,
    )
}

fn open_filesystem_with_live_args(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    live_args: serde_json::Value,
) -> LocalFileSystem {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let pool_name = pool.unwrap_or("<unnamed>");
        let metadata_dir = import_devices_metadata_dir(devs, pool_name, operation, live_args);

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

    let path = match (backing_dir, pool) {
        (Some(path), _) => {
            super::live_owner::route_if_owner_exists_for_backing_dir_with_args(
                "snapshot", operation, path, live_args,
            );
            super::offline_pool::refuse_runtime_pool_path("snapshot", operation, path);
            path.clone()
        }
        (None, Some(pool_name)) => {
            super::live_owner::route_with_args("snapshot", operation, pool_name, live_args)
        }
        (None, None) => {
            eprintln!("tidefsctl snapshot {operation}: POOL is required");
            process::exit(1);
        }
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

fn import_devices_metadata_dir(
    devices: &[PathBuf],
    pool_name: &str,
    operation: &str,
    live_args: serde_json::Value,
) -> PathBuf {
    let config = scan_device_pool_config(pool_name, devices, operation);
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "snapshot",
        operation,
        pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        live_args,
    );

    super::offline_pool::metadata_dir("snapshot", operation, &config.pool_uuid)
}

fn scan_device_pool_config(
    pool_name: &str,
    devices: &[PathBuf],
    operation: &str,
) -> tidefs_pool_scan::PoolConfig {
    let entries = match tidefs_pool_scan::scan_labels(devices) {
        Ok(entries) => entries,
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot {operation}: pool label scan failed for '{pool_name}': {err}"
            );
            process::exit(1);
        }
    };
    let config = match tidefs_pool_scan::PoolAssembler::assemble(&entries, None) {
        Ok(config) => config,
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot {operation}: pool assembly failed for '{pool_name}': {err}"
            );
            process::exit(1);
        }
    };
    if pool_name != "<unnamed>" && config.pool_name != pool_name {
        eprintln!(
            "tidefsctl snapshot {operation}: devices belong to pool '{}', not '{pool_name}'",
            config.pool_name
        );
        process::exit(1);
    }
    config
}

fn root_authentication_key() -> RootAuthenticationKey {
    RootAuthenticationKey::from_environment().unwrap_or_else(|_| RootAuthenticationKey::demo_key())
}

fn parse_named_snapshot_operands(
    operation: &str,
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> (Option<String>, String) {
    match (backing_dir.is_some(), operands) {
        (true, [name]) => (None, name.clone()),
        (true, []) => {
            eprintln!("tidefsctl snapshot {operation}: snapshot name is required");
            process::exit(1);
        }
        (true, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: directory-backed object-store mode is retired"
            );
            process::exit(1);
        }
        (false, [pool, name]) => (Some(pool.clone()), name.clone()),
        (false, [single]) => {
            eprintln!(
                "tidefsctl snapshot {operation}: '{single}' is ambiguous; use '<pool> <snapshot>'"
            );
            process::exit(1);
        }
        (false, []) => {
            eprintln!("tidefsctl snapshot {operation}: pool and snapshot name are required");
            process::exit(1);
        }
        (false, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: expected '<pool> <snapshot>' for live pool mode"
            );
            process::exit(1);
        }
    }
}

fn parse_pair_snapshot_operands(
    operation: &str,
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> (Option<String>, String, String) {
    match (backing_dir.is_some(), operands) {
        (true, [name, source]) => (None, name.clone(), source.clone()),
        (true, []) | (true, [_]) => {
            eprintln!("tidefsctl snapshot {operation}: entry name and source name are required");
            process::exit(1);
        }
        (true, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: directory-backed object-store mode is retired"
            );
            process::exit(1);
        }
        (false, [pool, name, source]) => (Some(pool.clone()), name.clone(), source.clone()),
        (false, []) | (false, [_]) | (false, [_, _]) => {
            eprintln!(
                "tidefsctl snapshot {operation}: expected '<pool> <entry> <source>' for live pool mode"
            );
            process::exit(1);
        }
        (false, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: expected '<pool> <entry> <source>' for live pool mode"
            );
            process::exit(1);
        }
    }
}

fn parse_optional_snapshot_operand(
    operation: &str,
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> (Option<String>, Option<String>) {
    match (backing_dir.is_some(), operands) {
        (true, []) => (None, None),
        (true, [name]) => (None, Some(name.clone())),
        (true, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: directory-backed object-store mode is retired"
            );
            process::exit(1);
        }
        (false, [pool]) => (Some(pool.clone()), None),
        (false, [pool, name]) => (Some(pool.clone()), Some(name.clone())),
        (false, []) => {
            eprintln!("tidefsctl snapshot {operation}: pool name is required");
            process::exit(1);
        }
        (false, _) => {
            eprintln!(
                "tidefsctl snapshot {operation}: expected '<pool> [snapshot-or-clone]' for live pool mode"
            );
            process::exit(1);
        }
    }
}

fn snapshot_kind_label(kind: SnapshotKind) -> &'static str {
    match kind {
        SnapshotKind::Snapshot => "snapshot",
        SnapshotKind::Clone => "clone",
        SnapshotKind::Bookmark => "bookmark",
    }
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

fn snapshot_descriptor_line(descriptor: &SnapshotDescriptor) -> String {
    let kind = snapshot_kind_label(descriptor.kind);
    let origin = descriptor
        .origin
        .as_ref()
        .map(|origin| format!("'{origin}'"))
        .unwrap_or_else(|| "-".to_string());
    format!(
        "snapshot entry '{}' kind={} origin={} holds={} source tx={} source gen={} created gen={}",
        descriptor.name,
        kind,
        origin,
        descriptor.hold_count,
        descriptor.source_transaction_id,
        descriptor.source_generation,
        descriptor.created_at_generation
    )
}

fn hold_info_line(info: &HoldInfo) -> String {
    format!(
        "snapshot hold '{}' kind={} holds={}",
        info.snapshot_name,
        snapshot_kind_label(info.kind),
        info.hold_count
    )
}

fn retention_policy_from_args(args: &SnapshotPruneArgs) -> Result<SnapshotRetentionPolicy, String> {
    if args.keep_latest.is_none() && args.max_age_generations.is_none() {
        return Err(
            "no effective retention policy; pass --keep-latest or --max-age-generations".into(),
        );
    }
    Ok(SnapshotRetentionPolicy {
        max_count: args.keep_latest,
        max_age_generations: args.max_age_generations,
    })
}

fn snapshot_names(summaries: &[SnapshotSummary]) -> String {
    if summaries.is_empty() {
        return "-".into();
    }
    summaries
        .iter()
        .map(|summary| summary.name.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn retention_policy_summary(policy: &SnapshotRetentionPolicy) -> String {
    let keep_latest = policy
        .max_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "-".into());
    let max_age_generations = policy
        .max_age_generations
        .map(|generations| generations.to_string())
        .unwrap_or_else(|| "-".into());
    format!("keep_latest={keep_latest}, max_age_generations={max_age_generations}")
}

fn retention_report_lines(report: &SnapshotRetentionReport) -> Vec<String> {
    vec![
        format!(
            "snapshot retention prune evaluated gen {} -> published gen {} ({}, pruned={}, retained={}, skipped held={}, excluded catalog entries={})",
            report.evaluated_at_generation,
            report.published_generation,
            retention_policy_summary(&report.policy),
            report.pruned_snapshots.len(),
            report.retained_snapshots.len(),
            report.skipped_held_snapshots.len(),
            report.excluded_catalog_entries
        ),
        format!("pruned snapshots: {}", snapshot_names(&report.pruned_snapshots)),
        format!(
            "retained snapshots: {}",
            snapshot_names(&report.retained_snapshots)
        ),
        format!(
            "skipped held snapshots: {}",
            snapshot_names(&report.skipped_held_snapshots)
        ),
    ]
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

fn snapshot_backing_path(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    live_args: serde_json::Value,
) -> PathBuf {
    match (backing_dir, pool, devices.filter(|devs| !devs.is_empty())) {
        (Some(p), _, _) => {
            super::live_owner::route_if_owner_exists_for_backing_dir_with_args(
                "snapshot", operation, p, live_args,
            );
            super::offline_pool::refuse_runtime_pool_path("snapshot", operation, p);
            p.clone()
        }
        (None, pool_name, Some(devs)) => import_devices_metadata_dir(
            devs,
            pool_name.unwrap_or("<unnamed>"),
            operation,
            serde_json::Value::Null,
        ),
        (None, Some(pool_name), None) => super::live_owner::route_with_args(
            "snapshot",
            operation,
            pool_name,
            live_args,
        ),
        (None, None, None) => {
            eprintln!("tidefsctl snapshot send: POOL required");
            process::exit(1);
        }
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
    let _guard = super::authz::require_local_only("snapshot create");

    let (pool, snapshot_name) =
        parse_named_snapshot_operands("create", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "create",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &snapshot_name,
        }),
    );

    match fs.create_snapshot(&snapshot_name) {
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
    let mut snapshots = fs.list_snapshots_extended();
    snapshots.sort_by(|a, b| {
        a.created_at_generation
            .cmp(&b.created_at_generation)
            .then_with(|| a.name.cmp(&b.name))
    });

    if snapshots.is_empty() {
        println!("no snapshots");
        return;
    }

    for descriptor in snapshots {
        println!("{}", snapshot_descriptor_line(&descriptor));
    }
}

fn handle_clone(cmd: SnapshotCloneCommand) {
    match cmd {
        SnapshotCloneCommand::Create(args) => handle_clone_create(args),
        SnapshotCloneCommand::Delete(args) => handle_clone_delete(args),
        SnapshotCloneCommand::Promote(args) => handle_clone_promote(args),
    }
}

fn handle_clone_create(args: SnapshotCloneCreateArgs) {
    let _guard = super::authz::require_local_only("snapshot clone create");

    let (pool, clone_name, source_name) =
        parse_pair_snapshot_operands("clone create", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "clone create",
        RecoveryPolicy::default(),
        serde_json::json!({
            "clone": &clone_name,
            "source": &source_name,
        }),
    );

    match fs.create_clone(&clone_name, &source_name) {
        Ok(summary) => {
            println!(
                "clone '{}' created from '{}' (source tx={}, source gen={}, created gen={})",
                summary.name,
                summary.origin,
                summary.source_transaction_id,
                summary.source_generation,
                summary.created_at_generation
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot clone create: failed to create clone '{clone_name}' from '{source_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_clone_delete(args: SnapshotCloneDeleteArgs) {
    let _guard = super::authz::require_local_only("snapshot clone delete");

    let (pool, clone_name) =
        parse_named_snapshot_operands("clone delete", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "clone delete",
        RecoveryPolicy::default(),
        serde_json::json!({
            "clone": &clone_name,
        }),
    );

    match fs.delete_clone(&clone_name) {
        Ok(summary) => {
            println!(
                "clone '{}' deleted (source tx={}, source gen={}, created gen={})",
                summary.name,
                summary.source_transaction_id,
                summary.source_generation,
                summary.created_at_generation
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot clone delete: failed to delete clone '{clone_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_clone_promote(args: SnapshotClonePromoteArgs) {
    let _guard = super::authz::require_local_only("snapshot clone promote");

    let (pool, clone_name) =
        parse_named_snapshot_operands("clone promote", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "clone promote",
        RecoveryPolicy::default(),
        serde_json::json!({
            "clone": &clone_name,
        }),
    );

    match fs.promote_clone(&clone_name) {
        Ok(report) => {
            println!(
                "clone '{}' promoted to snapshot (previous origin='{}', generation={})",
                report.name, report.previous_origin, report.generation
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot clone promote: failed to promote clone '{clone_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_bookmark(cmd: SnapshotBookmarkCommand) {
    match cmd {
        SnapshotBookmarkCommand::Create(args) => handle_bookmark_create(args),
        SnapshotBookmarkCommand::Delete(args) => handle_bookmark_delete(args),
    }
}

fn handle_bookmark_create(args: SnapshotBookmarkCreateArgs) {
    let _guard = super::authz::require_local_only("snapshot bookmark create");

    let (pool, bookmark_name, source_name) =
        parse_pair_snapshot_operands("bookmark create", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "bookmark create",
        RecoveryPolicy::default(),
        serde_json::json!({
            "bookmark": &bookmark_name,
            "source": &source_name,
        }),
    );

    match fs.create_bookmark(&bookmark_name, &source_name) {
        Ok(summary) => {
            println!(
                "bookmark '{}' created from '{}' (source tx={}, source gen={}, created gen={})",
                summary.name,
                summary.source_snapshot,
                summary.source_transaction_id,
                summary.source_generation,
                summary.created_at_generation
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot bookmark create: failed to create bookmark '{bookmark_name}' from '{source_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_bookmark_delete(args: SnapshotBookmarkDeleteArgs) {
    let _guard = super::authz::require_local_only("snapshot bookmark delete");

    let (pool, bookmark_name) =
        parse_named_snapshot_operands("bookmark delete", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "bookmark delete",
        RecoveryPolicy::default(),
        serde_json::json!({
            "bookmark": &bookmark_name,
        }),
    );

    match fs.delete_bookmark(&bookmark_name) {
        Ok(summary) => {
            println!(
                "bookmark '{}' deleted (source tx={}, source gen={}, created gen={})",
                summary.name,
                summary.source_transaction_id,
                summary.source_generation,
                summary.created_at_generation
            );
        }
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot bookmark delete: failed to delete bookmark '{bookmark_name}': {err}"
            );
            process::exit(1);
        }
    }
}

fn handle_hold(args: SnapshotHoldArgs) {
    let _guard = super::authz::require_local_only("snapshot hold");

    let (pool, name) =
        parse_named_snapshot_operands("hold", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "hold",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &name,
        }),
    );

    match fs.hold_snapshot(&name) {
        Ok(info) => {
            println!("{} held", hold_info_line(&info));
        }
        Err(err) => {
            eprintln!("tidefsctl snapshot hold: failed to hold '{name}': {err}");
            process::exit(1);
        }
    }
}

fn handle_release(args: SnapshotReleaseArgs) {
    let _guard = super::authz::require_local_only("snapshot release");

    let (pool, name) =
        parse_named_snapshot_operands("release", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "release",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &name,
        }),
    );

    match fs.release_snapshot(&name) {
        Ok(info) => {
            println!("{} released", hold_info_line(&info));
        }
        Err(err) => {
            eprintln!("tidefsctl snapshot release: failed to release '{name}': {err}");
            process::exit(1);
        }
    }
}

fn handle_holds(args: SnapshotHoldsArgs) {
    let (pool, name) =
        parse_optional_snapshot_operand("holds", args.backing_dir.as_ref(), &args.operands);
    let fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "holds",
        RecoveryPolicy::ReadOnly,
        serde_json::json!({
            "name": name.as_deref(),
        }),
    );

    if let Some(name) = name {
        match fs.hold_info(&name) {
            Ok(info) => println!("{}", hold_info_line(&info)),
            Err(err) => {
                eprintln!("tidefsctl snapshot holds: failed to inspect '{name}': {err}");
                process::exit(1);
            }
        }
        return;
    }

    let mut holds = fs.list_holds();
    holds.sort_by(|a, b| a.snapshot_name.cmp(&b.snapshot_name));
    if holds.is_empty() {
        println!("no snapshot holds");
        return;
    }
    for info in holds {
        println!("{}", hold_info_line(&info));
    }
}

fn handle_prune(args: SnapshotPruneArgs) {
    let _guard = super::authz::require_local_only("snapshot prune");

    let policy = match retention_policy_from_args(&args) {
        Ok(policy) => policy,
        Err(err) => {
            eprintln!("tidefsctl snapshot prune: {err}");
            process::exit(1);
        }
    };
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "prune",
        RecoveryPolicy::default(),
        serde_json::json!({
            "keep_latest": args.keep_latest,
            "max_age_generations": args.max_age_generations,
        }),
    );

    match fs.prune_snapshots(policy) {
        Ok(report) => {
            for line in retention_report_lines(&report) {
                println!("{line}");
            }
        }
        Err(err) => {
            eprintln!("tidefsctl snapshot prune: failed to prune snapshots: {err}");
            process::exit(1);
        }
    }
}

fn handle_destroy(args: SnapshotDestroyArgs) {
    let _guard = super::authz::require_local_only("snapshot destroy");

    let (pool, snapshot_name) =
        parse_named_snapshot_operands("destroy", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "destroy",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &snapshot_name,
        }),
    );

    // delete_snapshot validates the entry is a Snapshot (not clone/bookmark),
    // checks holds, unpins the SnapshotCatalog root from the GC pin set via
    // the embedded DatasetLifecycle, and removes the metadata from the catalog.
    match fs.delete_snapshot(&snapshot_name) {
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
    let _guard = super::authz::require_local_only("snapshot rollback");

    let (pool, snapshot_name) =
        parse_named_snapshot_operands("rollback", args.backing_dir.as_ref(), &args.operands);
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "rollback",
        RecoveryPolicy::default(),
        serde_json::json!({
            "name": &snapshot_name,
        }),
    );

    match fs.rollback_to_snapshot(&snapshot_name) {
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

fn handle_export(args: SnapshotExportArgs) {
    let _guard = super::authz::require_local_only("snapshot export");
    let _ = args;
    eprintln!(
        concat!(
            "tidefsctl snapshot export: runtime snapshot export is not yet implemented; ",
            "issue #765 will wire the read-only export session and issue #766 ",
            "will add export holds"
        )
    );
    process::exit(1);
}

fn handle_extract(args: SnapshotExtractArgs) {
    let _guard = super::authz::require_local_only("snapshot extract");
    let _ = args;
    eprintln!(
        concat!(
            "tidefsctl snapshot extract: runtime snapshot extraction is not yet ",
            "implemented; issue #925 will wire one-shot snapshot file reads"
        )
    );
    process::exit(1);
}

fn handle_send(args: SnapshotSendArgs) {
    let _guard = super::authz::require_local_only("snapshot send");

    let live_args = serde_json::json!({
        "output": args.output.as_ref().map(|path| path.display().to_string()),
        "target_addr": args.target_addr.map(|addr| addr.to_string()),
        "node_id": args.node_id,
        "server_node_id": args.server_node_id,
        "format": &args.format,
        "incremental": args.incremental,
        "from_root": args.from_root.as_deref(),
        "pool_id": args.pool_id.as_deref(),
        "dataset_id": args.dataset_id.as_deref(),
    });
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "send",
        RecoveryPolicy::default(),
        live_args.clone(),
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
            let path = snapshot_backing_path(
                args.backing_dir.as_ref(),
                args.pool.as_deref(),
                args.devices.as_deref(),
                "send",
                live_args.clone(),
            );
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
            let path = snapshot_backing_path(
                args.backing_dir.as_ref(),
                args.pool.as_deref(),
                args.devices.as_deref(),
                "send",
                live_args.clone(),
            );
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
    let _guard = super::authz::require_local_only("snapshot receive");

    if let Some(path) = args.backing_dir.as_ref() {
        eprintln!(
            "tidefsctl snapshot receive: {}",
            crate::commands::retired_directory_pool_media_message(&path.display().to_string())
        );
        process::exit(1);
    }

    let live_args = snapshot_receive_live_args(&args);

    super::live_owner::route_with_args("snapshot", "receive", &args.pool, live_args);
}

fn snapshot_receive_live_args(args: &SnapshotReceiveArgs) -> serde_json::Value {
    serde_json::json!({
        "input": args.input.as_ref().map(|path| path.display().to_string()),
        "source_addr": args.source_addr.map(|addr| addr.to_string()),
        "node_id": args.node_id,
        "server_node_id": args.server_node_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_snapshot_summary(name: &str) -> SnapshotSummary {
        SnapshotSummary {
            name: name.into(),
            source_transaction_id: 1,
            source_generation: 2,
            created_at_generation: 3,
            source_root: tidefs_local_filesystem::CommittedRootSummary {
                slot: 0,
                transaction_id: 1,
                generation: 2,
                next_inode_id: 3,
                inode_count: 4,
                superblock_checksum: tidefs_local_object_store::IntegrityDigest64(0),
                has_transaction_manifest: false,
                manifest_checksum: tidefs_local_object_store::IntegrityDigest64(0),
                manifest_entry_count: 0,
                has_root_authentication: false,
                root_authentication_policy_epoch: None,
                root_authentication_algorithm_suite_id: None,
                superblock_digest: None,
                manifest_digest: None,
                root_authentication_code: None,
            },
        }
    }

    #[test]
    fn snapshot_create_args_bindings() {
        let args = SnapshotCreateArgs {
            operands: vec!["before-upgrade".into()],
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            devices: None,
        };
        assert_eq!(args.operands, vec!["before-upgrade"]);
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
            operands: vec!["mysnap".into()],
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            devices: None,
        };
        assert_eq!(args.operands, vec!["mysnap"]);
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
    }

    #[test]
    fn snapshot_create_pool_args_bindings() {
        let args = SnapshotCreateArgs {
            operands: vec!["mypool".into(), "before-upgrade".into()],
            backing_dir: None,
            devices: Some(vec![PathBuf::from("/dev/sdb"), PathBuf::from("/dev/sdc")]),
        };
        assert_eq!(args.operands, vec!["mypool", "before-upgrade"]);
        assert_eq!(
            args.devices,
            Some(vec![PathBuf::from("/dev/sdb"), PathBuf::from("/dev/sdc")])
        );
    }

    #[test]
    fn snapshot_destroy_default_args() {
        let cmd = SnapshotCommand::Destroy(SnapshotDestroyArgs {
            operands: vec!["test".into()],
            backing_dir: Some(PathBuf::from("/backing")),
            devices: None,
        });
        match cmd {
            SnapshotCommand::Destroy(args) => {
                assert_eq!(args.operands, vec!["test"]);
                assert_eq!(args.backing_dir, Some(PathBuf::from("/backing")));
            }
            SnapshotCommand::Create(_)
            | SnapshotCommand::List(_)
            | SnapshotCommand::Clone(_)
            | SnapshotCommand::Bookmark(_)
            | SnapshotCommand::Hold(_)
            | SnapshotCommand::Release(_)
            | SnapshotCommand::Holds(_)
            | SnapshotCommand::Prune(_)
            | SnapshotCommand::Send(_)
            | SnapshotCommand::Receive(_)
            | SnapshotCommand::Rollback(_)
            | SnapshotCommand::Export(_)
            | SnapshotCommand::Extract(_) => {
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
            pool: "mypool".into(),
            backing_dir: None,
            input: Some(PathBuf::from("/tmp/stream.vfssend1")),
            source_addr: None,
            node_id: None,
            server_node_id: None,
        };
        assert_eq!(args.pool, "mypool");
        assert_eq!(args.backing_dir, None);
        assert_eq!(args.input, Some(PathBuf::from("/tmp/stream.vfssend1")));
        assert!(args.source_addr.is_none());
    }

    #[test]
    fn snapshot_receive_live_args_exclude_offline_media() {
        let args = SnapshotReceiveArgs {
            pool: "mypool".into(),
            backing_dir: None,
            input: Some(PathBuf::from("/tmp/stream.vfssend1")),
            source_addr: "127.0.0.1:9000".parse().ok(),
            node_id: Some(7),
            server_node_id: Some(9),
        };

        let live_args = snapshot_receive_live_args(&args);
        assert_eq!(
            live_args.get("input").and_then(|value| value.as_str()),
            Some("/tmp/stream.vfssend1")
        );
        assert_eq!(
            live_args
                .get("source_addr")
                .and_then(|value| value.as_str()),
            Some("127.0.0.1:9000")
        );
        assert!(!live_args.as_object().unwrap().contains_key("devices"));
        assert!(!live_args.as_object().unwrap().contains_key("backing_dir"));
    }

    #[test]
    fn snapshot_extended_line_reports_lifecycle_metadata() {
        let line = snapshot_descriptor_line(&SnapshotDescriptor {
            name: "clone-a".into(),
            kind: SnapshotKind::Clone,
            origin: Some("snap-a".into()),
            hold_count: 2,
            source_transaction_id: 7,
            source_generation: 9,
            created_at_generation: 11,
        });

        assert!(line.contains("kind=clone"));
        assert!(line.contains("origin='snap-a'"));
        assert!(line.contains("holds=2"));
        assert!(line.contains("source tx=7"));
        assert!(line.contains("source gen=9"));
        assert!(line.contains("created gen=11"));
    }

    #[test]
    fn snapshot_prune_rejects_empty_retention_policy() {
        let args = SnapshotPruneArgs {
            backing_dir: None,
            pool: Some("mypool".into()),
            devices: None,
            keep_latest: None,
            max_age_generations: None,
        };

        let err = retention_policy_from_args(&args).expect_err("empty policy rejected");
        assert!(err.contains("no effective retention policy"));
    }

    #[test]
    fn snapshot_prune_accepts_combined_retention_policy() {
        let args = SnapshotPruneArgs {
            backing_dir: None,
            pool: Some("mypool".into()),
            devices: Some(vec![PathBuf::from("/dev/sdb")]),
            keep_latest: Some(3),
            max_age_generations: Some(42),
        };

        let policy = retention_policy_from_args(&args).expect("retention policy");
        assert_eq!(policy.max_count, Some(3));
        assert_eq!(policy.max_age_generations, Some(42));
        assert_eq!(
            retention_policy_summary(&policy),
            "keep_latest=3, max_age_generations=42"
        );
    }

    #[test]
    fn snapshot_prune_report_lines_include_policy_counts_and_names() {
        let report = SnapshotRetentionReport {
            policy: SnapshotRetentionPolicy {
                max_count: Some(1),
                max_age_generations: Some(10),
            },
            evaluated_at_generation: 100,
            published_generation: 101,
            pruned_snapshots: vec![test_snapshot_summary("old")],
            retained_snapshots: vec![test_snapshot_summary("new")],
            skipped_held_snapshots: vec![test_snapshot_summary("held")],
            excluded_catalog_entries: 2,
        };

        let lines = retention_report_lines(&report);
        assert_eq!(
            lines[0],
            "snapshot retention prune evaluated gen 100 -> published gen 101 (keep_latest=1, max_age_generations=10, pruned=1, retained=1, skipped held=1, excluded catalog entries=2)"
        );
        assert_eq!(lines[1], "pruned snapshots: old");
        assert_eq!(lines[2], "retained snapshots: new");
        assert_eq!(lines[3], "skipped held snapshots: held");
    }

    #[test]
    fn snapshot_export_args_bindings() {
        let args = SnapshotExportArgs {
            snapshot_name: "mypool@mysnap".into(),
            export_path: PathBuf::from("/mnt/snap"),
        };
        assert_eq!(args.snapshot_name, "mypool@mysnap");
        assert_eq!(args.export_path, PathBuf::from("/mnt/snap"));
    }

    #[test]
    fn snapshot_extract_args_bindings() {
        let args = SnapshotExtractArgs {
            snapshot_name: "mypool@mysnap".into(),
            file_path: "/data/lostfile".into(),
            output: Some(PathBuf::from("/tmp/recovered")),
        };
        assert_eq!(args.snapshot_name, "mypool@mysnap");
        assert_eq!(args.file_path, "/data/lostfile");
        assert_eq!(args.output, Some(PathBuf::from("/tmp/recovered")));
    }

    #[test]
    fn snapshot_extract_args_defaults_to_stdout() {
        let args = SnapshotExtractArgs {
            snapshot_name: "mypool@daily.0".into(),
            file_path: "/etc/config".into(),
            output: None,
        };
        assert!(args.output.is_none());
    }

    #[test]
    fn snapshot_export_command_is_registered_in_enum() {
        let cmd = SnapshotCommand::Export(SnapshotExportArgs {
            snapshot_name: "mypool@snap1".into(),
            export_path: PathBuf::from("/mnt/snap"),
        });
        match cmd {
            SnapshotCommand::Export(args) => {
                assert_eq!(args.snapshot_name, "mypool@snap1");
                assert_eq!(args.export_path, PathBuf::from("/mnt/snap"));
            }
            _ => panic!("expected export command"),
        }
    }

    #[test]
    fn snapshot_extract_command_is_registered_in_enum() {
        let cmd = SnapshotCommand::Extract(SnapshotExtractArgs {
            snapshot_name: "mypool@snap1".into(),
            file_path: "/data/file".into(),
            output: None,
        });
        match cmd {
            SnapshotCommand::Extract(args) => {
                assert_eq!(args.snapshot_name, "mypool@snap1");
                assert_eq!(args.file_path, "/data/file");
            }
            _ => panic!("expected extract command"),
        }
    }
}
