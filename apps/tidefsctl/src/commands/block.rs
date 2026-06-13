//! `tidefsctl block` subcommands: attach, detach, and list ublk block
//! devices backed by a TideFS pool.
//!
//! # Entrypoint Authority
//!
//! `tidefsctl block attach <pool>` is the operator entrypoint for ublk block
//! device lifecycle. Imported pools route to the live owner. Directory
//! object-store backing is a hidden retired/offline path, not an
//! operator block-volume backing mode.
//!
//! The block-volume-adapter-daemon binary `ublk-serve` subcommand is a
//! development/harness tool and must not be used as a production device
//! lifecycle path.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Subcommand;
use tidefs_local_filesystem::RootAuthenticationKey;

/// Subcommands for the `tidefsctl block` group.
#[derive(Subcommand, Debug)]
pub enum BlockCommand {
    /// Attach a pool as a ublk block device and serve I/O
    Attach {
        /// Pool name. Imported pools route to the live owner.
        pool: String,

        /// Retired directory object-store backing mode.
        #[arg(
            short = 'b',
            long = "backing-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        backing_dir: Option<PathBuf>,

        /// Number of hardware queues (1..UBLK_MAX_NR_QUEUES)
        #[arg(long, default_value_t = 1)]
        nr_hw_queues: u16,

        /// I/O queue depth
        #[arg(long, default_value_t = 64)]
        queue_depth: u16,

        /// Drain deadline in seconds for graceful shutdown
        #[arg(long, default_value_t = 30)]
        drain_deadline_secs: u64,

        /// Enable io_uring dispatch path
        #[arg(long)]
        io_uring: bool,
    },

    /// Detach a ublk block device by its numeric device ID
    Detach {
        /// Numeric ublk device ID (e.g. 0 for /dev/ublkb0)
        device_id: u32,
    },

    /// List attached ublk block devices
    List,

    /// Send a block-volume snapshot over the network to a remote storage-node.
    Send {
        /// Pool name. Imported pools route to the live owner.
        pool: String,

        /// Retired directory object-store backing mode.
        #[arg(
            short = 'b',
            long = "backing-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        backing_dir: Option<PathBuf>,

        /// TCP address of the remote storage-node.
        #[arg(long = "target-addr")]
        target_addr: SocketAddr,

        /// Local node id for transport identity.
        #[arg(long = "node-id", default_value_t = 1)]
        node_id: u64,

        /// Remote storage-node id for transport routing.
        #[arg(long = "server-node-id", default_value_t = 2)]
        server_node_id: u64,
    },

    /// Receive a block-volume snapshot over the network from a remote storage-node.
    Receive {
        /// Pool name. Imported pools route to the live owner.
        pool: String,

        /// Retired directory object-store backing mode.
        #[arg(
            short = 'b',
            long = "backing-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        backing_dir: Option<PathBuf>,

        /// TCP address of the remote storage-node.
        #[arg(long = "source-addr")]
        source_addr: SocketAddr,

        /// Local node id for transport identity.
        #[arg(long = "node-id", default_value_t = 1)]
        node_id: u64,

        /// Remote storage-node id for transport routing.
        #[arg(long = "server-node-id", default_value_t = 2)]
        server_node_id: u64,
    },
}

/// Route a [`BlockCommand`] to the appropriate handler.
pub fn handle_block(cmd: BlockCommand) {
    match cmd {
        BlockCommand::Attach {
            pool,
            backing_dir,
            nr_hw_queues,
            queue_depth,
            drain_deadline_secs,
            io_uring,
        } => {
            if let Err(err) = handle_attach(
                &pool,
                backing_dir.as_deref(),
                nr_hw_queues,
                queue_depth,
                drain_deadline_secs,
                io_uring,
            ) {
                eprintln!("tidefsctl block attach: {err}");
                process::exit(1);
            }
        }
        BlockCommand::Detach { device_id } => {
            if let Err(err) = handle_detach(device_id) {
                eprintln!("tidefsctl block detach: {err}");
                process::exit(1);
            }
        }
        BlockCommand::List => {
            handle_list();
        }
        BlockCommand::Send {
            pool,
            backing_dir,
            target_addr,
            node_id,
            server_node_id,
        } => {
            if let Err(err) = handle_block_send(
                &pool,
                backing_dir.as_deref(),
                target_addr,
                node_id,
                server_node_id,
            ) {
                eprintln!("tidefsctl block send: {err}");
                process::exit(1);
            }
        }
        BlockCommand::Receive {
            pool,
            backing_dir,
            source_addr,
            node_id,
            server_node_id,
        } => {
            if let Err(err) = handle_block_receive(
                &pool,
                backing_dir.as_deref(),
                source_addr,
                node_id,
                server_node_id,
            ) {
                eprintln!("tidefsctl block receive: {err}");
                process::exit(1);
            }
        }
    }
}

// ── Attach ────────────────────────────────────────────────────────────

fn handle_attach(
    pool: &str,
    backing_dir: Option<&Path>,
    nr_hw_queues: u16,
    queue_depth: u16,
    drain_deadline_secs: u64,
    io_uring: bool,
) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block attach");

    let live_args = serde_json::json!({
        "nr_hw_queues": nr_hw_queues,
        "queue_depth": queue_depth,
        "drain_deadline_secs": drain_deadline_secs,
        "io_uring": io_uring,
    });

    let Some(pool_path) = backing_dir else {
        super::live_owner::route_with_args("block", "attach", pool, live_args);
    };

    super::live_owner::route_if_owner_exists_for_pool_backing_dir_with_args(
        "block",
        "attach",
        pool,
        pool_path,
        live_args.clone(),
    );
    super::offline_pool::refuse_runtime_pool_path("block", "attach", pool_path);

    if !pool_path.exists() {
        return Err(format!(
            "retired directory object-store backing does not exist: {}",
            pool_path.display()
        ));
    }
    if !pool_path.is_dir() {
        return Err(format!(
            "retired directory object-store backing is not a directory: {}",
            pool_path.display()
        ));
    }

    eprintln!(
        "tidefsctl block attach: opening retired directory object-store backing for pool '{pool}' at {}",
        pool_path.display()
    );

    use tidefs_block_volume_adapter_core::{BlockVolumeGeometryRecord, BlockVolumeId};
    use tidefs_block_volume_adapter_daemon::storage_backend::BlockVolumeObjectStoreBackend;
    use tidefs_block_volume_adapter_daemon::ublk_control_open::run_ublk_live_device;

    // Default geometry: 4 KiB blocks, 1 GiB capacity (262144 blocks), single shard.
    let geometry = BlockVolumeGeometryRecord::new(BlockVolumeId::new(301_200), 4096, 262_144, 1);

    // ── Crash recovery detection ──────────────────────────────────
    // Detect whether the previous shutdown was unclean and replay
    // intent-log segments before opening the backend. Recovery is
    // best-effort: failures are logged as warnings rather than
    // preventing pool attach.
    let mount_state_path = {
        let mut p = std::path::PathBuf::from(pool_path);
        p.push(".tidefs_mount_state_ublk");
        p
    };
    {
        use tidefs_recovery_loop::{CrashRecoveryLoop, CrashRecoveryState, MountState};
        match CrashRecoveryLoop::detect(&mount_state_path) {
            Ok(mut recovery) => {
                recovery.advance();
                if recovery.state == CrashRecoveryState::Replay {
                    eprintln!("tidefsctl block attach: unclean shutdown detected — replaying intent log...");
                    match tidefs_local_object_store::LocalObjectStore::open(pool_path) {
                        Ok(store) => {
                            if let Err(e) = recovery.run_replay(&store) {
                                eprintln!("tidefsctl block attach: warning: intent log replay failed: {e}; continuing");
                            } else {
                                recovery.reconcile_and_finish();
                                eprintln!("tidefsctl block attach: crash recovery complete — pool is ready.");
                            }
                        }
                        Err(e) => {
                            eprintln!("tidefsctl block attach: warning: cannot open store for crash recovery: {e}; continuing");
                        }
                    }
                }
                // Mark dirty for this session
                if let Err(e) = MountState::Dirty.write_to_path(&mount_state_path) {
                    eprintln!("tidefsctl block attach: warning: cannot write mount-state: {e}; continuing");
                }
            }
            Err(e) => {
                eprintln!("tidefsctl block attach: warning: crash recovery detection failed: {e}; continuing");
            }
        }
    }

    // ── Committed-root validation ──────────────────────────────────
    // Validate the committed root discovered during pool import.
    {
        let root_file = std::path::Path::new(pool_path).join("tidefs-committed-root");
        if let Ok(payload) = std::fs::read(&root_file) {
            if let Some((root, digest)) =
                tidefs_local_object_store::txg_manager::CommitGroupManager::decode_root_with_digest(
                    &payload,
                )
            {
                match tidefs_recovery_loop::recovery_loop::validate_committed_root(root, digest) {
                    Ok(()) => {
                        eprintln!(
                            "tidefsctl block attach: committed root validated: commit_group={} handle={}",
                            root.commit_group_id.0, root.root_handle,
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "tidefsctl block attach: warning: committed root validation failed: {e}; continuing with unvalidated root"
                        );
                    }
                }
            }
        }
    }

    let mut backend = BlockVolumeObjectStoreBackend::open(pool_path, geometry)
        .map_err(|e| format!("failed to open block backend: {e}"))?;

    eprintln!(
        "tidefsctl block attach: launching ublk live device (queues={nr_hw_queues} depth={queue_depth})"
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_thread =
        tidefs_block_volume_adapter_daemon::signal_shutdown::install_signal_shutdown_thread(
            "tidefsctl block attach",
            Arc::clone(&shutdown),
        )?;
    let report = run_ublk_live_device(
        None,
        &mut backend,
        Arc::clone(&shutdown),
        io_uring,
        nr_hw_queues,
        queue_depth,
        drain_deadline_secs,
    );
    signal_thread.finish();
    let report = report.map_err(|e| format!("ublk live device failed: {e}"))?;

    // ── Mark clean on successful shutdown ─────────────────────────
    {
        use tidefs_recovery_loop::MountState;
        if let Err(e) = MountState::Clean.write_to_path(&mount_state_path) {
            // Non-fatal: pool state was already persisted via sync/flush.
            eprintln!("tidefsctl block attach: warning: failed to write clean mount-state: {e}");
        }
    }

    report.print();
    Ok(())
}

// ── Detach ────────────────────────────────────────────────────────────

fn handle_detach(device_id: u32) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block detach");

    use std::fs::OpenOptions;
    use std::os::fd::AsFd;
    use std::os::unix::fs::FileTypeExt;

    let control_path = "/dev/ublk-control";

    let meta = std::fs::metadata(control_path)
        .map_err(|e| format!("cannot access {control_path}: {e}"))?;
    if !meta.file_type().is_char_device() {
        return Err(format!("{control_path} is not a character device"));
    }

    let control_fd = OpenOptions::new()
        .read(true)
        .write(true)
        .open(control_path)
        .map_err(|e| format!("cannot open {control_path}: {e}"))?;

    use tidefs_block_volume_adapter_ublk_control_runtime::{issue_del_dev, UblkControlDelDevInput};

    let input = UblkControlDelDevInput { dev_id: device_id };
    let fd = control_fd.as_fd();

    let outcome =
        issue_del_dev(fd, input).map_err(|e| format!("UBLK_CMD_DEL_DEV failed: {e:?}"))?;

    eprintln!(
        "tidefsctl block detach: device {} removed (dev_id={})",
        device_id, outcome.dev_id
    );

    Ok(())
}

// ── List ──────────────────────────────────────────────────────────────

fn handle_list() {
    let mut found = false;

    if let Ok(entries) = std::fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.starts_with("ublkb") {
                let path = entry.path();
                let size_info = read_block_device_size(&path)
                    .map(|s| format!("  size={s}"))
                    .unwrap_or_default();
                println!("{}{}", path.display(), size_info);
                found = true;
            }
        }
    }

    if !found {
        println!("No TideFS ublk block devices found.");
    }
}

/// Read the size of a block device via its sysfs `size` attribute.
fn read_block_device_size(dev_path: &Path) -> Result<u64, ()> {
    let dev_name = dev_path.file_name().ok_or(())?.to_string_lossy();
    let size_path = std::path::PathBuf::from("/sys/class/block")
        .join(dev_name.as_ref())
        .join("size");
    let content = std::fs::read_to_string(&size_path).map_err(|_| ())?;
    let sectors: u64 = content.trim().parse().map_err(|_| ())?;
    Ok(sectors * 512)
}

// ── Block send/receive over VSNP ─────────────────────────────────────

use crate::commands::snapshot::{
    build_block_pull_request, build_block_push_message, parse_snap_net_message, transport_request,
    SnapNetMessage,
};

fn block_root_auth_key() -> RootAuthenticationKey {
    RootAuthenticationKey::from_environment().unwrap_or_else(|_| RootAuthenticationKey::demo_key())
}

fn handle_block_send(
    pool: &str,
    backing_dir: Option<&Path>,
    target_addr: SocketAddr,
    node_id: u64,
    server_node_id: u64,
) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block send");

    let live_args = serde_json::json!({
        "target_addr": target_addr.to_string(),
        "node_id": node_id,
        "server_node_id": server_node_id,
    });

    let Some(pool_path) = backing_dir else {
        super::live_owner::route_with_args("block", "send", pool, live_args);
    };

    super::live_owner::route_if_owner_exists_for_pool_backing_dir_with_args(
        "block",
        "send",
        pool,
        pool_path,
        live_args.clone(),
    );
    super::offline_pool::refuse_runtime_pool_path("block", "send", pool_path);

    if !pool_path.exists() {
        return Err(format!(
            "retired directory object-store backing does not exist: {}",
            pool_path.display()
        ));
    }

    // Read raw block data from the pool's block-volume storage.
    let block_data = read_pool_block_data(pool_path)?;
    let device_name = "block-volume";
    let auth_key = block_root_auth_key();
    let req = build_block_push_message(&block_data, device_name, &auth_key.as_bytes32());

    eprintln!(
        "block send: pushing {} bytes to {target_addr}",
        block_data.len()
    );

    let response = transport_request(node_id, server_node_id, target_addr, req)
        .map_err(|e| format!("transport: {e}"))?;

    match parse_snap_net_message(&response) {
        Ok(SnapNetMessage::Ack { message }) => {
            println!("block send: {message}");
        }
        Ok(SnapNetMessage::Error { message }) => {
            return Err(format!("remote error: {message}"));
        }
        _ => {
            return Err("bad response from server".into());
        }
    }

    Ok(())
}

fn handle_block_receive(
    pool: &str,
    backing_dir: Option<&Path>,
    source_addr: SocketAddr,
    node_id: u64,
    server_node_id: u64,
) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block receive");

    let live_args = serde_json::json!({
        "source_addr": source_addr.to_string(),
        "node_id": node_id,
        "server_node_id": server_node_id,
    });

    let Some(pool_path) = backing_dir else {
        super::live_owner::route_with_args("block", "receive", pool, live_args);
    };

    super::live_owner::route_if_owner_exists_for_pool_backing_dir_with_args(
        "block",
        "receive",
        pool,
        pool_path,
        live_args.clone(),
    );
    super::offline_pool::refuse_runtime_pool_path("block", "receive", pool_path);

    if pool_path.exists() {
        return Err(format!(
            "destination retired directory object-store backing already exists: {} (receive requires an empty target)",
            pool_path.display()
        ));
    }

    let auth_key = block_root_auth_key();
    let req = build_block_pull_request("block-volume", &auth_key.as_bytes32());

    eprintln!("block receive: pulling from {source_addr}");

    let response = transport_request(node_id, server_node_id, source_addr, req)
        .map_err(|e| format!("transport: {e}"))?;

    let block_data = match parse_snap_net_message(&response) {
        Ok(SnapNetMessage::PullResponse { export }) => export,
        Ok(SnapNetMessage::Error { message }) => {
            return Err(format!("remote error: {message}"));
        }
        _ => {
            return Err("bad response from server".into());
        }
    };

    write_pool_block_data(pool_path, &block_data)?;

    println!(
        "block receive: wrote {} bytes to {}",
        block_data.len(),
        pool_path.display()
    );
    Ok(())
}

/// Read the raw block data from a TideFS pool's block-volume storage.
fn read_pool_block_data(pool_path: &Path) -> Result<Vec<u8>, String> {
    // Read committed-root metadata to determine block-volume extent.
    let root_file = pool_path.join("tidefs-committed-root");
    if !root_file.exists() {
        return Err("no committed-root found; pool may not be initialized".into());
    }

    // Collect all objects in the pool directory as raw block data.
    // For a production implementation, this would use the block-volume
    // adapter's read path. The current approach reads object store files
    // directly as a simple block-level replication.
    let mut block_data = Vec::new();
    let dir_entries = std::fs::read_dir(pool_path).map_err(|e| format!("read pool dir: {e}"))?;

    for entry in dir_entries {
        let entry = entry.map_err(|e| format!("dir entry: {e}"))?;
        let path = entry.path();
        if path.is_file()
            && path
                .file_name()
                .map(|n| n != "tidefs-committed-root")
                .unwrap_or(true)
        {
            let data = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            block_data.extend_from_slice(&data);
        }
    }

    if block_data.is_empty() {
        return Err("pool contains no block data".into());
    }

    Ok(block_data)
}

/// Write raw block data to a TideFS pool.
fn write_pool_block_data(pool_path: &Path, data: &[u8]) -> Result<(), String> {
    std::fs::create_dir_all(pool_path).map_err(|e| format!("create pool dir: {e}"))?;

    // Write block data as a single object file in the pool.
    let data_path = pool_path.join("block-volume-data");
    std::fs::write(&data_path, data).map_err(|e| format!("write block data: {e}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_attach_rejects_nonexistent_path() {
        let result = handle_attach(
            "mypool",
            Some(Path::new("/tmp/tidefs-nonexistent-pool-xyz")),
            4,
            64,
            30,
            false,
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .contains("retired directory object-store backing does not exist"),);
    }

    #[test]
    fn block_detach_rejects_missing_control_device() {
        let result = handle_detach(0);
        assert!(result.is_err());
    }

    #[test]
    fn block_list_does_not_panic() {
        handle_list();
    }

    #[test]
    fn read_block_device_size_nonexistent() {
        let result = read_block_device_size(Path::new("/dev/nonexistent-ublkb99999"));
        assert!(result.is_err());
    }
}
