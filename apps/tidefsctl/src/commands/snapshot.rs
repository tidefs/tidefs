// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Snapshot subcommands.
//!
//! Wires CLI arguments to `tidefs_local_filesystem::LocalFileSystem` to
//! create, list, and destroy point-in-time snapshot state. The explicit
//! `replication-io` feature also exposes stream send and receive.

#[cfg(feature = "replication-io")]
use std::fs;
#[cfg(feature = "remote-snapshot")]
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
#[cfg(feature = "replication-io")]
use tidefs_local_filesystem::{ChangedRecordExport, RootAuthenticationKey};
use tidefs_local_filesystem::{
    HoldInfo, LocalFileSystem, LocalFileSystemOpenConfig, LocalStorageAllocatorPolicy,
    RecoveryPolicy, SnapshotDescriptor, SnapshotKind, SnapshotRetentionPolicy,
    SnapshotRetentionReport, SnapshotSummary,
};
use tidefs_local_object_store::{PoolRedundancyPolicy, StoreOptions};
use tidefs_pool_runtime::{PoolRuntime, VolumeCloneSummary, VolumeSnapshotSummary};
#[cfg(feature = "remote-snapshot")]
use tidefs_transport::{NodeInfo, SessionCloseReason, Transport};
use tidefs_vfs_engine::{LivePoolAdminArg, LivePoolAdminArgs};

// ---------------------------------------------------------------------------
// Snapshot network transfer protocol (simple VFSSEND1 push/pull via VSNP)
// ---------------------------------------------------------------------------

#[cfg(feature = "remote-snapshot")]
const SNAP_NET_MAGIC: &[u8; 4] = b"VSNP";
#[cfg(feature = "remote-snapshot")]
const SNAP_KIND_ERROR: u8 = 0;
#[cfg(feature = "remote-snapshot")]
const SNAP_KIND_PUSH: u8 = 1;
#[cfg(feature = "remote-snapshot")]
const SNAP_KIND_PULL_REQUEST: u8 = 2;
#[cfg(feature = "remote-snapshot")]
const SNAP_KIND_PULL_RESPONSE: u8 = 3;
#[cfg(feature = "remote-snapshot")]
pub(crate) const SNAP_KIND_ACK: u8 = 4;

#[cfg(feature = "remote-snapshot")]
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
#[cfg(feature = "remote-snapshot")]
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
#[cfg(feature = "remote-snapshot")]
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
#[cfg(feature = "remote-snapshot")]
pub(crate) enum SnapNetMessage {
    Push { auth_key: [u8; 32], export: Vec<u8> },
    PullRequest { auth_key: [u8; 32] },
    PullResponse { export: Vec<u8> },
    Ack { message: String },
    Error { message: String },
}

#[cfg(feature = "remote-snapshot")]
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

#[cfg(feature = "remote-snapshot")]
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
    /// Manage writable local volume clones from canonical snapshots
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
    /// Inspect and control live scheduled snapshot pruning
    #[command(name = "prune-scheduled")]
    PruneScheduled(SnapshotPruneScheduledArgs),
    /// Destroy a named snapshot, unpinning its object graph from GC
    Destroy(SnapshotDestroyArgs),
    /// Export a changed-record snapshot stream from the current filesystem root
    #[cfg(feature = "replication-io")]
    Send(SnapshotSendArgs),
    /// Receive a changed-record snapshot stream through the live pool owner
    #[cfg(feature = "replication-io")]
    Receive(SnapshotReceiveArgs),
    /// Rollback the dataset to a named snapshot state
    Rollback(SnapshotRollbackArgs),
    /// Register the runtime-pending read-only snapshot export mount surface
    Export(SnapshotExportArgs),
    /// Extract one file from a snapshot through the live owner
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
    /// Create a writable volume clone from a canonical volume snapshot
    Create(SnapshotCloneCreateArgs),
    /// Delete an unpromoted writable volume clone
    Delete(SnapshotCloneDeleteArgs),
    /// Promote a writable volume clone to an independent volume
    Promote(SnapshotClonePromoteArgs),
}

/// `snapshot clone create <pool> <clone> <volume@snapshot> [--devices <dev>...]`
#[derive(Args, Debug)]
pub struct SnapshotCloneCreateArgs {
    /// Pool that owns the snapshot and clone
    pub pool: String,

    /// Writable clone dataset path
    pub clone: String,

    /// Canonical source volume@snapshot path
    #[arg(value_name = "VOLUME@SNAPSHOT")]
    pub source: String,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported volume-clone access
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
    /// Pool that owns the clone
    pub pool: String,

    /// Writable volume-clone dataset path
    pub clone: String,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported volume-clone access
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
    /// Pool that owns the clone
    pub pool: String,

    /// Writable volume-clone dataset path
    pub clone: String,

    /// Retired directory object-store backing mode.
    #[arg(
        long = "backing-dir",
        short = 'b',
        hide = true,
        value_parser = crate::commands::reject_directory_pool_media_value
    )]
    pub backing_dir: Option<PathBuf>,

    /// Block devices for offline/not-yet-imported volume-clone access
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

/// `snapshot prune-scheduled <policy|plan|enable|disable|status|refusals|results> <pool>`
#[derive(Args, Debug)]
pub struct SnapshotPruneScheduledArgs {
    #[command(subcommand)]
    pub cmd: SnapshotPruneScheduledCommand,
}

/// Subcommands for `snapshot prune-scheduled`.
#[derive(Subcommand, Debug)]
pub enum SnapshotPruneScheduledCommand {
    /// Show the scheduled prune policy admission state
    Policy(SnapshotPruneScheduledPoolArgs),
    /// Show the current scheduled prune dry-run plan
    Plan(SnapshotPruneScheduledPoolArgs),
    /// Admit destructive scheduled prune execution
    Enable(SnapshotPruneScheduledPoolArgs),
    /// Disable destructive scheduled prune execution
    Disable(SnapshotPruneScheduledPoolArgs),
    /// Show scheduled prune job status
    Status(SnapshotPruneScheduledPoolArgs),
    /// Show current scheduled prune refusal reasons
    Refusals(SnapshotPruneScheduledPoolArgs),
    /// Show recent scheduled prune result summaries
    Results(SnapshotPruneScheduledPoolArgs),
}

/// Pool selector for scheduled prune operator commands.
#[derive(Args, Debug)]
pub struct SnapshotPruneScheduledPoolArgs {
    /// Pool name for live scheduled prune visibility and controls
    pub pool: String,
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
#[cfg(feature = "replication-io")]
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

    #[cfg(feature = "remote-snapshot")]
    /// Push the stream to a remote storage-node via transport.
    #[arg(
        long = "target-addr",
        requires = "node_id",
        requires = "server_node_id"
    )]
    pub target_addr: Option<SocketAddr>,

    #[cfg(feature = "remote-snapshot")]
    #[arg(long = "node-id", requires = "target-addr")]
    pub node_id: Option<u64>,

    #[cfg(feature = "remote-snapshot")]
    #[arg(long = "server-node-id", requires = "target-addr")]
    pub server_node_id: Option<u64>,

    /// Stream format: vfssend1 (default) or vfssend2.
    #[arg(long = "format", default_value = "vfssend1")]
    pub format: String,

    /// Send an incremental delta from the specified base root.
    /// The hex key encodes (tid: u64, gen: u64, csum: u64) = 48 hex chars = 24 bytes.
    #[arg(long = "incremental")]
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
#[cfg(feature = "replication-io")]
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

    #[cfg(feature = "remote-snapshot")]
    /// Pull a stream from a remote storage-node via transport.
    #[arg(
        long = "source-addr",
        requires = "node_id",
        requires = "server_node_id"
    )]
    pub source_addr: Option<SocketAddr>,

    #[cfg(feature = "remote-snapshot")]
    #[arg(long = "node-id", requires = "source_addr")]
    pub node_id: Option<u64>,

    #[cfg(feature = "remote-snapshot")]
    #[arg(long = "server-node-id", requires = "source_addr")]
    pub server_node_id: Option<u64>,

    /// Operator merge policy for conflicting non-empty receive targets.
    ///
    /// Governs how diverged objects are resolved: keep-local (target wins),
    /// keep-remote (stream wins), merge-latest (higher-txg wins, target-wins
    /// tiebreak), or manual (refuse, report conflict inventory).
    #[arg(long = "merge-policy", value_parser = ["keep-local", "keep-remote", "merge-latest", "manual"])]
    pub merge_policy: Option<String>,
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

/// `snapshot export <snapshot-name> <export-path> [--store <path>]`
/// Open a read-only FUSE session backed by a named snapshot.
/// Snapshot names follow the `@` prefix convention, e.g. `mypool@mysnap`.
#[derive(Args, Debug)]
pub struct SnapshotExportArgs {
    /// Pool and snapshot name in pool@snapshot form
    #[arg(
        value_name = "SNAPSHOT_NAME",
        help = "Snapshot name in pool@snapshot form"
    )]
    pub snapshot_name: String,

    /// Mount path for the read-only FUSE export session
    #[arg(
        value_name = "EXPORT_PATH",
        help = "Filesystem path where the snapshot is mounted read-only"
    )]
    pub export_path: PathBuf,

    /// Pool store root directory (the directory containing the TideFS store)
    #[arg(
        long = "store",
        value_name = "STORE_PATH",
        help = "Pool store root directory; required when the pool has no reachable live FUSE owner"
    )]
    pub store_path: Option<PathBuf>,
}

/// `snapshot extract <snapshot-name> <file-path>`
/// Extract a regular file from a named snapshot.
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
        SnapshotCommand::PruneScheduled(args) => handle_prune_scheduled(args.cmd),
        SnapshotCommand::Destroy(args) => handle_destroy(args),
        #[cfg(feature = "replication-io")]
        SnapshotCommand::Send(args) => handle_send(args),
        #[cfg(feature = "replication-io")]
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
        LivePoolAdminArgs::default(),
    )
}

fn open_filesystem_with_live_args(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    recovery_policy: RecoveryPolicy,
    live_args: LivePoolAdminArgs,
) -> LocalFileSystem {
    if let Some(devs) = devices.filter(|devs| !devs.is_empty()) {
        let pool_name = pool.unwrap_or("<unnamed>");
        let (metadata_dir, device_pool_name, pool_redundancy_policy) =
            import_devices_metadata_dir(devs, pool_name, operation, live_args);

        let root_auth_key =
            super::root_authentication_key_or_exit(&format!("snapshot {operation}"));
        return match LocalFileSystem::open_with_block_devices_and_recovery_policy(
            &metadata_dir,
            devs,
            &device_pool_name,
            pool_redundancy_policy,
            StoreOptions::default(),
            root_auth_key,
            recovery_policy,
        ) {
            Ok(fs) => fs,
            Err(err) => {
                eprintln!(
                    "tidefsctl snapshot {operation}: failed to open block-device-backed pool '{device_pool_name}' at {}: {err}",
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
            root_authentication_key: super::root_authentication_key_or_exit(&format!(
                "snapshot {operation}"
            )),
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
    live_args: LivePoolAdminArgs,
) -> (PathBuf, String, PoolRedundancyPolicy) {
    let config = scan_device_pool_config(pool_name, devices, operation);
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "snapshot",
        operation,
        pool_name,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        live_args,
    );

    let metadata_dir = super::offline_pool::metadata_dir("snapshot", operation, &config.pool_uuid);
    let redundancy_policy = PoolRedundancyPolicy::from_label_policy(config.redundancy_policy);
    (metadata_dir, config.pool_name, redundancy_policy)
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

fn parse_volume_snapshot_target(raw: &str) -> Result<(String, String, String), String> {
    let (pool, path) = raw
        .split_once('/')
        .ok_or_else(|| "expected snapshot target in <pool>/<volume>@<snapshot> form".to_string())?;
    let pool = crate::parser::parse_pool_name(pool)?;
    let (source, snapshot) = path
        .rsplit_once('@')
        .ok_or_else(|| "expected snapshot target in <pool>/<volume>@<snapshot> form".to_string())?;
    if source.contains('@') || snapshot.contains('/') {
        return Err("volume snapshot target must name one source and one snapshot".to_string());
    }
    let source = crate::parser::parse_dataset_path(source)?;
    let snapshot = crate::parser::parse_dataset_path(snapshot)?;
    Ok((pool, format!("{source}@{snapshot}"), source))
}

fn parse_volume_clone_create_operands(
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> Result<(String, String, String), String> {
    if backing_dir.is_some() {
        return Err("directory-backed object-store clone mode is retired".to_string());
    }
    let [pool, clone, source] = operands else {
        return Err(
            "expected '<pool> <clone> <volume@snapshot>' for writable volume clone creation"
                .to_string(),
        );
    };
    let pool = crate::parser::parse_pool_name(pool)?;
    let clone = crate::parser::parse_dataset_path(clone)?;
    if clone.contains('@') {
        return Err("volume clone target must be an ordinary dataset path".to_string());
    }
    if !source.contains('@') {
        return Err(format!(
            "source '{source}' is a filesystem snapshot alias, not an independently writable dataset; filesystem clone creation is unsupported until filesystem roots have dataset-scoped object namespaces"
        ));
    }
    let (source_pool, source, _) = parse_volume_snapshot_target(&format!("{pool}/{source}"))?;
    debug_assert_eq!(source_pool, pool);
    Ok((pool, clone, source))
}

fn parse_volume_clone_target_operands(
    operation: &str,
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> Result<(String, String), String> {
    if backing_dir.is_some() {
        return Err("directory-backed object-store clone mode is retired".to_string());
    }
    let [pool, clone] = operands else {
        return Err(format!(
            "expected '<pool> <clone>' for writable volume clone {operation}"
        ));
    };
    let pool = crate::parser::parse_pool_name(pool)?;
    let clone = crate::parser::parse_dataset_path(clone)?;
    if clone.contains('@') {
        return Err("volume clone target must be an ordinary dataset path".to_string());
    }
    Ok((pool, clone))
}

enum NamedSnapshotTarget {
    Filesystem { pool: Option<String>, name: String },
    Volume { pool: String, target: String },
}

fn parse_named_snapshot_target(
    operation: &str,
    backing_dir: Option<&PathBuf>,
    operands: &[String],
) -> NamedSnapshotTarget {
    if backing_dir.is_none() {
        if let [target] = operands {
            let (pool, target, _) = parse_volume_snapshot_target(target)
                .unwrap_or_else(|error| volume_snapshot_exit(operation, error, false));
            return NamedSnapshotTarget::Volume { pool, target };
        }
    }
    let (pool, name) = parse_named_snapshot_operands(operation, backing_dir, operands);
    NamedSnapshotTarget::Filesystem { pool, name }
}

fn with_offline_volume_snapshot_runtime<T>(
    pool: &str,
    devices: &[PathBuf],
    operation: &str,
    json: bool,
    live_args: &LivePoolAdminArgs,
    run: impl FnOnce(&mut PoolRuntime) -> Result<T, String>,
) -> T {
    let config = scan_device_pool_config(pool, devices, operation);
    super::live_owner::route_or_refuse_active_for_uuid_with_format_and_args(
        "snapshot",
        operation,
        pool,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        json,
        live_args.clone(),
    );
    let lock_dir = PathBuf::from("/run/tidefs/import");
    let import_owner = match tidefs_pool_import::pool_import_owned(devices, &lock_dir, false, None)
    {
        Ok(owner) => owner,
        Err(tidefs_pool_import::ImportError::AlreadyImported { pool_uuid }) => {
            super::live_owner::route_imported_with_format_and_args(
                "snapshot",
                operation,
                pool,
                pool_uuid,
                json,
                live_args.clone(),
            )
        }
        Err(err) => volume_snapshot_exit(operation, format!("pool import failed: {err}"), json),
    };
    let metadata_dir = super::offline_pool::metadata_dir("snapshot", operation, &config.pool_uuid);
    let result = (|| -> Result<T, String> {
        let mut runtime = PoolRuntime::open_block_devices(
            &metadata_dir,
            devices,
            pool,
            PoolRedundancyPolicy::from_label_policy(config.redundancy_policy),
            &StoreOptions::default(),
        )
        .map_err(|err| format!("failed to open canonical Pool runtime: {err}"))?;
        run(&mut runtime)
    })();
    let export_result = import_owner
        .export()
        .map_err(|err| format!("failed to export Pool after snapshot {operation}: {err}"));
    match (result, export_result) {
        (Ok(value), Ok(())) => value,
        (Err(error), Ok(())) => volume_snapshot_exit(operation, error, json),
        (Ok(_), Err(error)) => volume_snapshot_exit(operation, error, json),
        (Err(error), Err(export_error)) => volume_snapshot_exit(
            operation,
            format!("{error}; additionally {export_error}"),
            json,
        ),
    }
}

fn volume_snapshot_exit(operation: &str, error: String, json: bool) -> ! {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": false,
                "operation": operation,
                "error": error,
            })
        );
    } else {
        eprintln!("tidefsctl snapshot {operation}: {error}");
    }
    process::exit(1)
}

#[cfg(feature = "replication-io")]
fn root_authentication_key() -> RootAuthenticationKey {
    super::root_authentication_key_or_exit("snapshot send")
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SnapshotCapacityClassification {
    capacity_class: &'static str,
    lifecycle_state: &'static str,
    retained_root: &'static str,
    retained_byte_consumer: &'static str,
    pinned_snapshot_bytes: &'static str,
    deadlist_bytes: &'static str,
    reclaimable_bytes: &'static str,
}

fn snapshot_capacity_classification(kind: SnapshotKind) -> SnapshotCapacityClassification {
    match kind {
        SnapshotKind::Snapshot | SnapshotKind::Clone => SnapshotCapacityClassification {
            capacity_class: "retained-root",
            lifecycle_state: "unavailable",
            retained_root: "yes",
            retained_byte_consumer: "yes",
            pinned_snapshot_bytes: "unavailable",
            deadlist_bytes: "unavailable",
            reclaimable_bytes: "unavailable",
        },
        SnapshotKind::Bookmark => SnapshotCapacityClassification {
            capacity_class: "metadata-anchor",
            lifecycle_state: "not-applicable",
            retained_root: "no",
            retained_byte_consumer: "no",
            pinned_snapshot_bytes: "not-applicable",
            deadlist_bytes: "not-applicable",
            reclaimable_bytes: "not-applicable",
        },
    }
}

fn snapshot_descriptor_line(descriptor: &SnapshotDescriptor) -> String {
    let kind = snapshot_kind_label(descriptor.kind);
    let capacity = snapshot_capacity_classification(descriptor.kind);
    let origin = descriptor
        .origin
        .as_ref()
        .map(|origin| format!("'{origin}'"))
        .unwrap_or_else(|| "-".to_string());
    format!(
        "snapshot entry '{}' kind={} origin={} holds={} capacity_class={} lifecycle_state={} retained_root={} retained_byte_consumer={} pinned_snapshot_bytes={} deadlist_bytes={} reclaimable_bytes={} source tx={} source gen={} created gen={}",
        descriptor.name,
        kind,
        origin,
        descriptor.hold_count,
        capacity.capacity_class,
        capacity.lifecycle_state,
        capacity.retained_root,
        capacity.retained_byte_consumer,
        capacity.pinned_snapshot_bytes,
        capacity.deadlist_bytes,
        capacity.reclaimable_bytes,
        descriptor.source_transaction_id,
        descriptor.source_generation,
        descriptor.created_at_generation
    )
}

fn hold_info_line(info: &HoldInfo) -> String {
    let tag_part = info
        .hold_tag
        .as_ref()
        .map(|t| format!(" tag={t}"))
        .unwrap_or_default();
    format!(
        "snapshot hold '{}' kind={} holds={}{tag_part}",
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
#[cfg(feature = "replication-io")]
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

#[cfg(feature = "replication-io")]
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

#[cfg(feature = "replication-io")]
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

#[cfg(feature = "replication-io")]
fn snapshot_backing_path(
    backing_dir: Option<&PathBuf>,
    pool: Option<&str>,
    devices: Option<&[PathBuf]>,
    operation: &str,
    live_args: LivePoolAdminArgs,
) -> PathBuf {
    match (backing_dir, pool, devices.filter(|devs| !devs.is_empty())) {
        (Some(p), _, _) => {
            super::live_owner::route_if_owner_exists_for_backing_dir_with_args(
                "snapshot", operation, p, live_args,
            );
            super::offline_pool::refuse_runtime_pool_path("snapshot", operation, p);
            p.clone()
        }
        (None, pool_name, Some(devs)) => {
            import_devices_metadata_dir(
                devs,
                pool_name.unwrap_or("<unnamed>"),
                operation,
                LivePoolAdminArgs::default(),
            )
            .0
        }
        (None, Some(pool_name), None) => {
            super::live_owner::route_with_args("snapshot", operation, pool_name, live_args)
        }
        (None, None, None) => {
            eprintln!("tidefsctl snapshot send: POOL required");
            process::exit(1);
        }
    }
}

#[cfg(feature = "replication-io")]
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

    let target = parse_named_snapshot_target("create", args.backing_dir.as_ref(), &args.operands);
    let NamedSnapshotTarget::Filesystem {
        pool,
        name: snapshot_name,
    } = target
    else {
        let NamedSnapshotTarget::Volume { pool, target } = target else {
            unreachable!()
        };
        return handle_volume_snapshot_create(&pool, &target, args.devices.as_deref());
    };
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "create",
        RecoveryPolicy::default(),
        super::live_owner::live_admin_args([(
            "name",
            LivePoolAdminArg::String(snapshot_name.clone()),
        )]),
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

fn handle_volume_snapshot_create(pool: &str, target: &str, devices: Option<&[PathBuf]>) {
    let live_args =
        super::live_owner::live_admin_args([("target", LivePoolAdminArg::String(target.into()))]);
    let summary = if let Some(devices) = devices.filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            pool,
            devices,
            "create",
            false,
            &live_args,
            |runtime| {
                runtime
                    .create_volume_snapshot(target)
                    .map_err(|err| err.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args("snapshot", "create", pool, false, live_args)
    };
    print_volume_snapshot_outcome("created", &summary, false);
}

fn handle_volume_snapshot_restore(pool: &str, target: &str, devices: Option<&[PathBuf]>) {
    let live_args =
        super::live_owner::live_admin_args([("target", LivePoolAdminArg::String(target.into()))]);
    let result = if let Some(devices) = devices.filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            pool,
            devices,
            "rollback",
            false,
            &live_args,
            |runtime| {
                runtime
                    .restore_volume_snapshot(target)
                    .map_err(|err| err.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args(
            "snapshot", "rollback", pool, false, live_args,
        )
    };
    println!(
        "volume snapshot '{}' restored to '{}' (size={} generation={} resize_generation={} snapshot_generation={})",
        result.snapshot.path,
        result.snapshot.source_path,
        result.geometry.capacity_bytes,
        result.generation,
        result.resize_generation,
        result.snapshot_generation,
    );
}

fn handle_volume_snapshot_destroy(pool: &str, target: &str, devices: Option<&[PathBuf]>) {
    let live_args =
        super::live_owner::live_admin_args([("target", LivePoolAdminArg::String(target.into()))]);
    let summary = if let Some(devices) = devices.filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            pool,
            devices,
            "destroy",
            false,
            &live_args,
            |runtime| {
                runtime
                    .destroy_volume_snapshot(target)
                    .map_err(|err| err.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args("snapshot", "destroy", pool, false, live_args)
    };
    print_volume_snapshot_outcome("logically destroyed", &summary, false);
}

fn volume_snapshot_line(summary: &VolumeSnapshotSummary) -> String {
    format!(
        "volume snapshot '{}' source='{}' kind=volume source_generation={} snapshot_generation={} size={} block_size={}",
        summary.path,
        summary.source_path,
        summary.source_generation,
        summary.snapshot_generation,
        summary.geometry.capacity_bytes,
        summary.geometry.block_size_bytes,
    )
}

fn volume_snapshot_json(summary: &VolumeSnapshotSummary) -> serde_json::Value {
    serde_json::json!({
        "path": summary.path,
        "id": summary.snapshot_id.to_string(),
        "source": summary.source_path,
        "source_id": summary.source_dataset_id.to_string(),
        "source_kind": "volume",
        "source_generation": summary.source_generation,
        "snapshot_generation": summary.snapshot_generation,
        "size": summary.geometry.capacity_bytes,
        "block_size": summary.geometry.block_size_bytes,
    })
}

fn print_volume_snapshot_outcome(outcome: &str, summary: &VolumeSnapshotSummary, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "outcome": outcome,
                "physical_reclaim": false,
                "snapshot": volume_snapshot_json(summary),
            })
        );
    } else {
        println!("{} {outcome}", volume_snapshot_line(summary));
        if outcome == "logically destroyed" {
            println!("physical reclaim remains pending; no secure-erasure claim is made");
        }
    }
}

fn volume_clone_line(summary: &VolumeCloneSummary) -> String {
    format!(
        "volume clone '{}' source_snapshot='{}' source_volume='{}' kind=volume promoted={} generation={} size={} block_size={}",
        summary.path,
        summary.source_snapshot_path,
        summary.source_volume_path,
        summary.promoted,
        summary.generation,
        summary.geometry.capacity_bytes,
        summary.geometry.block_size_bytes,
    )
}

fn volume_clone_json(summary: &VolumeCloneSummary) -> serde_json::Value {
    serde_json::json!({
        "path": summary.path,
        "id": summary.clone_id.to_string(),
        "source_snapshot": summary.source_snapshot_path,
        "source_snapshot_id": summary.source_snapshot_id.to_string(),
        "source_volume": summary.source_volume_path,
        "source_volume_id": summary.source_volume_id.to_string(),
        "kind": "volume",
        "promoted": summary.promoted,
        "generation": summary.generation,
        "size": summary.geometry.capacity_bytes,
        "block_size": summary.geometry.block_size_bytes,
    })
}

fn print_volume_clone_outcome(outcome: &str, summary: &VolumeCloneSummary, json: bool) {
    if json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "outcome": outcome,
                "physical_reclaim": false,
                "clone": volume_clone_json(summary),
            })
        );
    } else {
        println!("{} {outcome}", volume_clone_line(summary));
        if outcome == "logically destroyed" {
            println!("physical reclaim remains pending; no secure-erasure claim is made");
        }
    }
}

fn handle_list(args: SnapshotListArgs) {
    if args.backing_dir.is_none() && args.devices.as_deref().is_none_or(<[_]>::is_empty) {
        let pool = args
            .pool
            .as_deref()
            .unwrap_or_else(|| volume_snapshot_exit("list", "pool is required".into(), false));
        super::live_owner::route_with_args("snapshot", "list", pool, LivePoolAdminArgs::default());
    }

    let offline_volume_snapshots =
        if let (Some(pool), Some(devices)) = (args.pool.as_deref(), args.devices.as_deref()) {
            let (has_filesystem, volume_snapshots) = with_offline_volume_snapshot_runtime(
                pool,
                devices,
                "list",
                false,
                &LivePoolAdminArgs::default(),
                |runtime| {
                    let has_filesystem = runtime
                        .dataset_root(tidefs_pool_runtime::ROOT_DATASET_ID)
                        .is_some_and(|root| {
                            root.kind == tidefs_pool_runtime::DatasetRootKind::Filesystem
                        });
                    runtime
                        .list_volume_snapshots()
                        .map(|snapshots| (has_filesystem, snapshots))
                        .map_err(|err| err.to_string())
                },
            );
            if !has_filesystem {
                print_snapshot_list(Vec::new(), volume_snapshots);
                return;
            }
            Some(volume_snapshots)
        } else {
            None
        };

    let fs = open_filesystem(
        args.backing_dir.as_ref(),
        args.pool.as_deref(),
        args.devices.as_deref(),
        "list",
        RecoveryPolicy::ReadOnly,
    );
    let mut snapshots = fs.list_snapshots_extended_checked().unwrap_or_else(|err| {
        volume_snapshot_exit(
            "list",
            format!("failed to list filesystem snapshots: {err}"),
            false,
        )
    });
    snapshots.sort_by(|a, b| {
        a.created_at_generation
            .cmp(&b.created_at_generation)
            .then_with(|| a.name.cmp(&b.name))
    });
    let volume_snapshots = offline_volume_snapshots.unwrap_or_else(|| {
        fs.list_volume_snapshot_datasets().unwrap_or_else(|err| {
            volume_snapshot_exit(
                "list",
                format!("failed to list volume snapshots: {err}"),
                false,
            )
        })
    });
    print_snapshot_list(snapshots, volume_snapshots);
}

fn print_snapshot_list(
    filesystem_snapshots: Vec<SnapshotDescriptor>,
    volume_snapshots: Vec<VolumeSnapshotSummary>,
) {
    if filesystem_snapshots.is_empty() && volume_snapshots.is_empty() {
        println!("no snapshots");
        return;
    }
    for descriptor in filesystem_snapshots {
        println!("{}", snapshot_descriptor_line(&descriptor));
    }
    for summary in volume_snapshots {
        println!("{}", volume_snapshot_line(&summary));
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

    let SnapshotCloneCreateArgs {
        pool: pool_operand,
        clone: clone_operand,
        source: source_operand,
        backing_dir,
        devices,
    } = args;
    let operands = [pool_operand, clone_operand, source_operand];
    let (pool, clone_name, source_name) =
        parse_volume_clone_create_operands(backing_dir.as_ref(), &operands)
            .unwrap_or_else(|error| volume_snapshot_exit("clone create", error, false));
    let live_args = super::live_owner::live_admin_args([
        ("clone", LivePoolAdminArg::String(clone_name.clone())),
        ("source", LivePoolAdminArg::String(source_name.clone())),
    ]);
    let summary = if let Some(devices) = devices.as_deref().filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            &pool,
            devices,
            "clone-create",
            false,
            &live_args,
            |runtime| {
                runtime
                    .create_volume_clone(&clone_name, &source_name)
                    .map_err(|error| error.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args(
            "snapshot",
            "clone-create",
            &pool,
            false,
            live_args,
        )
    };
    print_volume_clone_outcome("created", &summary, false);
}

fn handle_clone_delete(args: SnapshotCloneDeleteArgs) {
    let _guard = super::authz::require_local_only("snapshot clone delete");

    let SnapshotCloneDeleteArgs {
        pool: pool_operand,
        clone: clone_operand,
        backing_dir,
        devices,
    } = args;
    let operands = [pool_operand, clone_operand];
    let (pool, clone_name) =
        parse_volume_clone_target_operands("delete", backing_dir.as_ref(), &operands)
            .unwrap_or_else(|error| volume_snapshot_exit("clone delete", error, false));
    let live_args = super::live_owner::live_admin_args([(
        "clone",
        LivePoolAdminArg::String(clone_name.clone()),
    )]);
    let summary = if let Some(devices) = devices.as_deref().filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            &pool,
            devices,
            "clone-delete",
            false,
            &live_args,
            |runtime| {
                runtime
                    .destroy_volume_clone(&clone_name)
                    .map_err(|error| error.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args(
            "snapshot",
            "clone-delete",
            &pool,
            false,
            live_args,
        )
    };
    print_volume_clone_outcome("logically destroyed", &summary, false);
}

fn handle_clone_promote(args: SnapshotClonePromoteArgs) {
    let _guard = super::authz::require_local_only("snapshot clone promote");

    let SnapshotClonePromoteArgs {
        pool: pool_operand,
        clone: clone_operand,
        backing_dir,
        devices,
    } = args;
    let operands = [pool_operand, clone_operand];
    let (pool, clone_name) =
        parse_volume_clone_target_operands("promotion", backing_dir.as_ref(), &operands)
            .unwrap_or_else(|error| volume_snapshot_exit("clone promote", error, false));
    let live_args = super::live_owner::live_admin_args([(
        "clone",
        LivePoolAdminArg::String(clone_name.clone()),
    )]);
    let summary = if let Some(devices) = devices.as_deref().filter(|devices| !devices.is_empty()) {
        with_offline_volume_snapshot_runtime(
            &pool,
            devices,
            "clone-promote",
            false,
            &live_args,
            |runtime| {
                runtime
                    .promote_volume_clone(&clone_name)
                    .map_err(|error| error.to_string())
            },
        )
    } else {
        super::live_owner::route_with_format_and_args(
            "snapshot",
            "clone-promote",
            &pool,
            false,
            live_args,
        )
    };
    print_volume_clone_outcome("promoted", &summary, false);
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
        super::live_owner::live_admin_args([
            ("bookmark", LivePoolAdminArg::String(bookmark_name.clone())),
            ("source", LivePoolAdminArg::String(source_name.clone())),
        ]),
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
        super::live_owner::live_admin_args([(
            "bookmark",
            LivePoolAdminArg::String(bookmark_name.clone()),
        )]),
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
        super::live_owner::live_admin_args([("name", LivePoolAdminArg::String(name.clone()))]),
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
        super::live_owner::live_admin_args([("name", LivePoolAdminArg::String(name.clone()))]),
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
        super::live_owner::live_admin_args([(
            "name",
            super::live_owner::live_admin_optional_string(name.clone()),
        )]),
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
        super::live_owner::live_admin_args([
            (
                "keep_latest",
                super::live_owner::live_admin_optional_u64(
                    args.keep_latest.map(|value| value as u64),
                ),
            ),
            (
                "max_age_generations",
                super::live_owner::live_admin_optional_u64(args.max_age_generations),
            ),
        ]),
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

fn handle_prune_scheduled(cmd: SnapshotPruneScheduledCommand) {
    match cmd {
        SnapshotPruneScheduledCommand::Policy(args) => {
            print_scheduled_prune_read_only("policy", &args.pool);
        }
        SnapshotPruneScheduledCommand::Plan(args) => {
            print_scheduled_prune_read_only("dry-run plan", &args.pool);
        }
        SnapshotPruneScheduledCommand::Enable(args) => {
            let _guard = super::authz::require_local_only("snapshot prune-scheduled enable");
            print_scheduled_prune_control("enable", &args.pool);
        }
        SnapshotPruneScheduledCommand::Disable(args) => {
            let _guard = super::authz::require_local_only("snapshot prune-scheduled disable");
            print_scheduled_prune_control("disable", &args.pool);
        }
        SnapshotPruneScheduledCommand::Status(args) => {
            print_scheduled_prune_read_only("job status", &args.pool);
        }
        SnapshotPruneScheduledCommand::Refusals(args) => {
            print_scheduled_prune_read_only("refusal reasons", &args.pool);
        }
        SnapshotPruneScheduledCommand::Results(args) => {
            print_scheduled_prune_read_only("result summaries", &args.pool);
        }
    }
}

fn print_scheduled_prune_read_only(surface: &str, pool: &str) {
    println!("scheduled snapshot prune {surface} for pool '{pool}': unavailable");
    println!(
        "refusal: live scheduled prune policy, scheduler job state, and result evidence are not implemented in this operator slice"
    );
}

fn print_scheduled_prune_control(action: &str, pool: &str) {
    println!("scheduled snapshot prune destructive {action} for pool '{pool}': refused");
    println!(
        "refusal: destructive scheduled pruning is not admitted until dataset policy and scheduler job authority provide live evidence"
    );
}

fn handle_destroy(args: SnapshotDestroyArgs) {
    let _guard = super::authz::require_local_only("snapshot destroy");

    let target = parse_named_snapshot_target("destroy", args.backing_dir.as_ref(), &args.operands);
    let NamedSnapshotTarget::Filesystem {
        pool,
        name: snapshot_name,
    } = target
    else {
        let NamedSnapshotTarget::Volume { pool, target } = target else {
            unreachable!()
        };
        return handle_volume_snapshot_destroy(&pool, &target, args.devices.as_deref());
    };
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "destroy",
        RecoveryPolicy::default(),
        super::live_owner::live_admin_args([(
            "name",
            LivePoolAdminArg::String(snapshot_name.clone()),
        )]),
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

    let target = parse_named_snapshot_target("rollback", args.backing_dir.as_ref(), &args.operands);
    let NamedSnapshotTarget::Filesystem {
        pool,
        name: snapshot_name,
    } = target
    else {
        let NamedSnapshotTarget::Volume { pool, target } = target else {
            unreachable!()
        };
        return handle_volume_snapshot_restore(&pool, &target, args.devices.as_deref());
    };
    let mut fs = open_filesystem_with_live_args(
        args.backing_dir.as_ref(),
        pool.as_deref(),
        args.devices.as_deref(),
        "rollback",
        RecoveryPolicy::default(),
        super::live_owner::live_admin_args([(
            "name",
            LivePoolAdminArg::String(snapshot_name.clone()),
        )]),
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

    // Parse pool@snapshot name convention.
    let (pool_name, snapshot_name) = match args.snapshot_name.split_once('@') {
        Some((pool, snap)) if !pool.is_empty() && !snap.is_empty() => {
            (pool.to_string(), snap.to_string())
        }
        _ => {
            eprintln!(
                "tidefsctl snapshot export: invalid snapshot name '{}'; expected pool@snapshot form (e.g. mypool@mysnap)",
                args.snapshot_name
            );
            process::exit(1);
        }
    };

    // Resolve the backing directory: explicit --store or route through the
    // live owner. When no live owner is reachable, --store is required.
    let backing_dir = if let Some(ref store_path) = args.store_path {
        super::live_owner::route_if_owner_exists_for_backing_dir_with_args(
            "snapshot",
            "export",
            store_path,
            super::live_owner::live_admin_args([
                (
                    "export_path",
                    LivePoolAdminArg::String(args.export_path.display().to_string()),
                ),
                (
                    "snapshot_name",
                    LivePoolAdminArg::String(snapshot_name.clone()),
                ),
            ]),
        );
        store_path.clone()
    } else {
        eprintln!(
            "tidefsctl snapshot export: no --store path provided and no live owner reachable for pool '{}'",
            pool_name
        );
        eprintln!(
            "tidefsctl snapshot export: provide --store <path> to the pool's TideFS store root directory"
        );
        process::exit(1);
    };

    let config = tidefs_posix_filesystem_adapter_daemon::MountConfig {
        encryption: None,
        backing_dir,
        mountpoint: args.export_path.clone(),
        pool_name: Some(pool_name),
        pool_redundancy_policy: tidefs_local_object_store::PoolRedundancyPolicy::default(),
        pool_uuid: None,
        foreground: true,
        debug: false,
        read_only: false,
        writeback_cache: false,
        coherency_profile:
            tidefs_posix_filesystem_adapter_daemon::coherency_profile::CoherencyProfile::Writeback,
        block_devices: None,
        import_owner: None,
        dataset_path: None,
        snapshot_name: Some(snapshot_name),
        mount_authority: tidefs_posix_filesystem_adapter_daemon::MountAuthority::standalone(),
        runtime: tidefs_posix_filesystem_adapter_daemon::MountRuntimeOptions::default(),
    };

    if let Err(err) = tidefs_posix_filesystem_adapter_daemon::run_mount(config) {
        eprintln!("tidefsctl snapshot export: {err}");
        process::exit(1);
    }
}

fn handle_extract(args: SnapshotExtractArgs) {
    let _guard = super::authz::require_local_only("snapshot extract");
    let (pool_name, snapshot_name) = match args.snapshot_name.split_once('@') {
        Some((pool, snap)) if !pool.is_empty() && !snap.is_empty() => {
            (pool.to_string(), snap.to_string())
        }
        _ => {
            eprintln!(
                "tidefsctl snapshot extract: invalid snapshot name '{}'; expected pool@snapshot form (e.g. mypool@mysnap)",
                args.snapshot_name
            );
            process::exit(1);
        }
    };
    let file_path = match LocalFileSystem::normalize_snapshot_extract_path(&args.file_path) {
        Ok(path) => path,
        Err(err) => {
            eprintln!(
                "tidefsctl snapshot extract: invalid file path '{}': {err}",
                args.file_path
            );
            process::exit(1);
        }
    };

    super::live_owner::route_with_args(
        "snapshot",
        "extract",
        &pool_name,
        super::live_owner::live_admin_args([
            (
                "snapshot_name",
                LivePoolAdminArg::String(snapshot_name.clone()),
            ),
            ("file_path", LivePoolAdminArg::String(file_path.clone())),
            (
                "output",
                super::live_owner::live_admin_optional_string(
                    args.output.as_ref().map(|path| path.display().to_string()),
                ),
            ),
        ]),
    );
}

#[cfg(feature = "replication-io")]
fn handle_send(args: SnapshotSendArgs) {
    let _guard = super::authz::require_local_only("snapshot send");

    let live_args = super::live_owner::live_admin_args([
        (
            "output",
            super::live_owner::live_admin_optional_string(
                args.output.as_ref().map(|path| path.display().to_string()),
            ),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "target_addr",
            super::live_owner::live_admin_optional_string(
                args.target_addr.map(|addr| addr.to_string()),
            ),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "node_id",
            super::live_owner::live_admin_optional_u64(args.node_id),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "server_node_id",
            super::live_owner::live_admin_optional_u64(args.server_node_id),
        ),
        ("format", LivePoolAdminArg::String(args.format.clone())),
        ("incremental", LivePoolAdminArg::Bool(args.incremental)),
        (
            "from_root",
            super::live_owner::live_admin_optional_string(args.from_root.clone()),
        ),
        (
            "pool_id",
            super::live_owner::live_admin_optional_string(args.pool_id.clone()),
        ),
        (
            "dataset_id",
            super::live_owner::live_admin_optional_string(args.dataset_id.clone()),
        ),
    ]);
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
    #[cfg(feature = "remote-snapshot")]
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
            #[cfg(feature = "remote-snapshot")]
            eprintln!("tidefsctl snapshot send: --output or --target-addr required");
            #[cfg(not(feature = "remote-snapshot"))]
            eprintln!("tidefsctl snapshot send: --output required");
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

#[cfg(feature = "replication-io")]
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

#[cfg(feature = "replication-io")]
fn snapshot_receive_live_args(args: &SnapshotReceiveArgs) -> LivePoolAdminArgs {
    super::live_owner::live_admin_args([
        (
            "input",
            super::live_owner::live_admin_optional_string(
                args.input.as_ref().map(|path| path.display().to_string()),
            ),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "source_addr",
            super::live_owner::live_admin_optional_string(
                args.source_addr.map(|addr| addr.to_string()),
            ),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "node_id",
            super::live_owner::live_admin_optional_u64(args.node_id),
        ),
        #[cfg(feature = "remote-snapshot")]
        (
            "server_node_id",
            super::live_owner::live_admin_optional_u64(args.server_node_id),
        ),
        (
            "merge_policy",
            super::live_owner::live_admin_optional_string(args.merge_policy.clone()),
        ),
    ])
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
    fn volume_snapshot_target_uses_canonical_shared_command_shape() {
        let target = parse_volume_snapshot_target("tank/vol@before").unwrap();
        assert_eq!(target, ("tank".into(), "vol@before".into(), "vol".into()));

        match parse_named_snapshot_target("create", None, &["tank/vol@before".into()]) {
            NamedSnapshotTarget::Volume { pool, target } => {
                assert_eq!(pool, "tank");
                assert_eq!(target, "vol@before");
            }
            NamedSnapshotTarget::Filesystem { .. } => panic!("expected volume snapshot target"),
        }
    }

    #[test]
    fn volume_snapshot_target_refuses_ambiguous_or_nested_snapshot_names() {
        assert!(parse_volume_snapshot_target("tank/vol").is_err());
        assert!(parse_volume_snapshot_target("tank/vol@snap/nested").is_err());
        assert!(parse_volume_snapshot_target("tank/vol@snap@nested").is_err());
    }

    #[test]
    fn volume_clone_operands_select_canonical_volume_snapshot_shape() {
        assert_eq!(
            parse_volume_clone_create_operands(
                None,
                &["tank".into(), "clone".into(), "vol@before".into()],
            )
            .unwrap(),
            ("tank".into(), "clone".into(), "vol@before".into())
        );
        assert_eq!(
            parse_volume_clone_target_operands(
                "promotion",
                None,
                &["tank".into(), "clone".into()],
            )
            .unwrap(),
            ("tank".into(), "clone".into())
        );
    }

    #[test]
    fn volume_clone_operands_truthfully_refuse_filesystem_snapshot_aliases() {
        let error = parse_volume_clone_create_operands(
            None,
            &["tank".into(), "clone".into(), "filesystem-before".into()],
        )
        .unwrap_err();
        assert!(error.contains("filesystem snapshot alias"));
        assert!(error.contains("not an independently writable dataset"));
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
            | SnapshotCommand::PruneScheduled(_)
            | SnapshotCommand::Rollback(_)
            | SnapshotCommand::Export(_)
            | SnapshotCommand::Extract(_) => {
                panic!("expected destroy command")
            }
            #[cfg(feature = "replication-io")]
            SnapshotCommand::Send(_) | SnapshotCommand::Receive(_) => {
                panic!("expected destroy command")
            }
        }
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn snapshot_send_args_bindings() {
        let args = SnapshotSendArgs {
            backing_dir: Some(PathBuf::from("/tmp/pool")),
            pool: None,
            devices: None,
            output: Some(PathBuf::from("/tmp/stream.vfssend1")),
            #[cfg(feature = "remote-snapshot")]
            target_addr: None,
            #[cfg(feature = "remote-snapshot")]
            node_id: None,
            #[cfg(feature = "remote-snapshot")]
            server_node_id: None,
            format: "vfssend1".into(),
            incremental: false,
            from_root: None,
            pool_id: None,
            dataset_id: None,
        };
        assert_eq!(args.backing_dir, Some(PathBuf::from("/tmp/pool")));
        assert_eq!(args.output, Some(PathBuf::from("/tmp/stream.vfssend1")));
        #[cfg(feature = "remote-snapshot")]
        assert!(args.target_addr.is_none());
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn snapshot_receive_args_bindings() {
        let args = SnapshotReceiveArgs {
            pool: "mypool".into(),
            backing_dir: None,
            input: Some(PathBuf::from("/tmp/stream.vfssend1")),
            #[cfg(feature = "remote-snapshot")]
            source_addr: None,
            #[cfg(feature = "remote-snapshot")]
            node_id: None,
            #[cfg(feature = "remote-snapshot")]
            server_node_id: None,
            merge_policy: None,
        };
        assert_eq!(args.pool, "mypool");
        assert_eq!(args.backing_dir, None);
        assert_eq!(args.input, Some(PathBuf::from("/tmp/stream.vfssend1")));
        #[cfg(feature = "remote-snapshot")]
        assert!(args.source_addr.is_none());
    }

    #[cfg(all(feature = "replication-io", feature = "remote-snapshot"))]
    #[test]
    fn snapshot_receive_live_args_exclude_offline_media() {
        let args = SnapshotReceiveArgs {
            pool: "mypool".into(),
            backing_dir: None,
            input: Some(PathBuf::from("/tmp/stream.vfssend1")),
            source_addr: "127.0.0.1:9000".parse().ok(),
            node_id: Some(7),
            server_node_id: Some(9),
            merge_policy: None,
        };

        let live_args = snapshot_receive_live_args(&args);
        assert_eq!(
            live_args.0.get("input"),
            Some(&LivePoolAdminArg::String("/tmp/stream.vfssend1".into()))
        );
        assert_eq!(
            live_args.0.get("source_addr"),
            Some(&LivePoolAdminArg::String("127.0.0.1:9000".into()))
        );
        assert!(!live_args.0.contains_key("devices"));
        assert!(!live_args.0.contains_key("backing_dir"));
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
    fn snapshot_extended_line_reports_snapshot_retained_root_capacity() {
        let line = snapshot_descriptor_line(&SnapshotDescriptor {
            name: "snap-a".into(),
            kind: SnapshotKind::Snapshot,
            origin: None,
            hold_count: 0,
            source_transaction_id: 7,
            source_generation: 9,
            created_at_generation: 11,
        });

        assert!(line.contains("kind=snapshot"));
        assert!(line.contains("capacity_class=retained-root"));
        assert!(line.contains("lifecycle_state=unavailable"));
        assert!(line.contains("retained_root=yes"));
        assert!(line.contains("retained_byte_consumer=yes"));
        assert!(line.contains("pinned_snapshot_bytes=unavailable"));
        assert!(line.contains("deadlist_bytes=unavailable"));
        assert!(line.contains("reclaimable_bytes=unavailable"));
    }

    #[test]
    fn snapshot_extended_line_reports_clone_retained_root_capacity() {
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
        assert!(line.contains("capacity_class=retained-root"));
        assert!(line.contains("lifecycle_state=unavailable"));
        assert!(line.contains("retained_root=yes"));
        assert!(line.contains("retained_byte_consumer=yes"));
        assert!(line.contains("pinned_snapshot_bytes=unavailable"));
        assert!(line.contains("deadlist_bytes=unavailable"));
        assert!(line.contains("reclaimable_bytes=unavailable"));
    }

    #[test]
    fn snapshot_extended_line_reports_bookmark_as_non_retaining_anchor() {
        let line = snapshot_descriptor_line(&SnapshotDescriptor {
            name: "bookmark-a".into(),
            kind: SnapshotKind::Bookmark,
            origin: None,
            hold_count: 0,
            source_transaction_id: 7,
            source_generation: 9,
            created_at_generation: 11,
        });

        assert!(line.contains("kind=bookmark"));
        assert!(line.contains("capacity_class=metadata-anchor"));
        assert!(line.contains("lifecycle_state=not-applicable"));
        assert!(line.contains("retained_root=no"));
        assert!(line.contains("retained_byte_consumer=no"));
        assert!(line.contains("pinned_snapshot_bytes=not-applicable"));
        assert!(line.contains("deadlist_bytes=not-applicable"));
        assert!(line.contains("reclaimable_bytes=not-applicable"));
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
            store_path: None,
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
            store_path: None,
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
