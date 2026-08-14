// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! `tidefsctl block` subcommands: attach, detach, and list ublk block
//! devices backed by a TideFS pool.
//!
//! # Entrypoint Authority
//!
//! `tidefsctl block attach <pool>/<volume>` is the operator entrypoint for
//! ublk block-device lifecycle. Imported pools route to the live owner;
//! explicit devices are imported through the same canonical Pool runtime.
//!
//! The block-volume-adapter-daemon binary `ublk-serve` subcommand is a
//! development/harness tool and must not be used as a production device
//! lifecycle path.

use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use clap::Subcommand;
use tidefs_vfs_engine::LivePoolAdminArg;

/// Subcommands for the `tidefsctl block` group.
#[derive(Subcommand, Debug)]
pub enum BlockCommand {
    /// Attach a pool as a ublk block device and serve I/O
    Attach {
        /// Named volume target in <pool>/<volume> form.
        target: String,

        /// Offline pool member devices. Omit only for a reachable live owner.
        #[arg(long, value_name = "DEVICE", num_args = 1..)]
        devices: Vec<PathBuf>,

        /// Number of hardware queues (1..UBLK_MAX_NR_QUEUES)
        #[arg(long, default_value_t = 1)]
        nr_hw_queues: u16,

        /// I/O queue depth
        #[arg(long, default_value_t = 64)]
        queue_depth: u16,

        /// Drain deadline in seconds for graceful shutdown
        #[arg(long, default_value_t = 30)]
        drain_deadline_secs: u64,
    },

    /// Detach a ublk block device by its numeric device ID
    Detach {
        /// Numeric ublk device ID (e.g. 0 for /dev/ublkb0)
        device_id: u32,
    },

    /// List attached ublk block devices
    List,
}

/// Route a [`BlockCommand`] to the appropriate handler.
pub fn handle_block(cmd: BlockCommand) {
    match cmd {
        BlockCommand::Attach {
            target,
            devices,
            nr_hw_queues,
            queue_depth,
            drain_deadline_secs,
        } => {
            if let Err(err) = handle_attach(
                &target,
                &devices,
                nr_hw_queues,
                queue_depth,
                drain_deadline_secs,
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
    }
}

// ── Attach ────────────────────────────────────────────────────────────

fn handle_attach(
    raw_target: &str,
    devices: &[PathBuf],
    nr_hw_queues: u16,
    queue_depth: u16,
    drain_deadline_secs: u64,
) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block attach");
    let target = crate::parser::parse_dataset_target(raw_target)?;

    let live_args = super::live_owner::live_admin_args([
        ("volume", LivePoolAdminArg::String(target.dataset.clone())),
        ("nr_hw_queues", LivePoolAdminArg::U64(nr_hw_queues.into())),
        ("queue_depth", LivePoolAdminArg::U64(queue_depth.into())),
        (
            "drain_deadline_secs",
            LivePoolAdminArg::U64(drain_deadline_secs),
        ),
    ]);

    if devices.is_empty() {
        super::live_owner::route_with_args("block", "attach", &target.pool, live_args);
    }

    let entries = tidefs_pool_scan::scan_labels(devices)
        .map_err(|err| format!("scan Pool devices: {err}"))?;
    let config = tidefs_pool_scan::PoolAssembler::assemble(&entries, None)
        .map_err(|err| format!("assemble Pool devices: {err}"))?;
    if config.pool_name != target.pool {
        return Err(format!(
            "devices belong to pool '{}', not requested pool '{}'",
            config.pool_name, target.pool
        ));
    }
    super::live_owner::route_or_refuse_active_for_uuid_with_args(
        "block",
        "attach",
        &target.pool,
        config.pool_uuid,
        config.state == tidefs_types_pool_label_core::PoolState::Active,
        live_args,
    );

    use tidefs_block_volume_adapter_daemon::storage_backend::{
        PoolVolumeBackend, SharedPoolRuntime,
    };
    use tidefs_block_volume_adapter_daemon::ublk_control_open::run_ublk_live_device;
    use tidefs_pool_runtime::PoolRuntime;
    use tidefs_posix_filesystem_adapter_daemon::live_owner::{start_block_owner, LiveOwnerConfig};

    let lock_dir = PathBuf::from("/run/tidefs/import");
    let import_owner = tidefs_pool_import::pool_import_owned(devices, &lock_dir, false, None)
        .map_err(|err| format!("import Pool: {err}"))?;
    let metadata_dir = super::offline_pool::metadata_dir("block", "attach", &config.pool_uuid);
    let runtime = match PoolRuntime::open_block_devices(
        &metadata_dir,
        devices,
        &target.pool,
        tidefs_local_object_store::PoolRedundancyPolicy::from_label_policy(
            config.redundancy_policy,
        ),
        &tidefs_local_object_store::StoreOptions::default(),
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            return Err(combine_export_error(
                format!("open canonical Pool runtime: {error}"),
                import_owner.export(),
            ));
        }
    };
    let runtime = SharedPoolRuntime::new(std::sync::Mutex::new(runtime));
    let mut backend =
        match PoolVolumeBackend::open_shared(Arc::clone(&runtime), &target.dataset, false) {
            Ok(backend) => backend,
            Err(error) => {
                drop(runtime);
                return Err(combine_export_error(
                    format!("open Pool volume '{}': {error}", target.dataset),
                    import_owner.export(),
                ));
            }
        };

    eprintln!(
        "tidefsctl block attach: launching ublk live device (queues={nr_hw_queues} depth={queue_depth})"
    );

    let shutdown = Arc::new(AtomicBool::new(false));
    let signal_thread =
        match tidefs_block_volume_adapter_daemon::signal_shutdown::install_signal_shutdown_thread(
            "tidefsctl block attach",
            Arc::clone(&shutdown),
        ) {
            Ok(signal_thread) => signal_thread,
            Err(error) => {
                drop(backend);
                drop(runtime);
                return Err(combine_export_error(error, import_owner.export()));
            }
        };
    let runtime_dir = PathBuf::from("/run/tidefs/pools").join(hex_uuid(&config.pool_uuid));
    let owner_config = LiveOwnerConfig {
        pool_name: target.pool.clone(),
        pool_uuid: config.pool_uuid,
        backing_dir: metadata_dir,
        mountpoint: PathBuf::from(format!("ublk:{}", target.dataset)),
        runtime_dir,
        read_only: false,
    };
    let live_owner = match start_block_owner(
        owner_config,
        Arc::clone(&runtime),
        target.dataset.clone(),
        Arc::clone(&shutdown),
    ) {
        Ok(owner) => owner,
        Err(error) => {
            signal_thread.finish();
            drop(backend);
            drop(runtime);
            return Err(combine_export_error(
                format!("start ublk live owner: {error}"),
                import_owner.export(),
            ));
        }
    };
    let carrier_result = run_ublk_live_device(
        None,
        &mut backend,
        Arc::clone(&shutdown),
        false,
        nr_hw_queues,
        queue_depth,
        drain_deadline_secs,
    );
    live_owner.standalone_block_carrier_stopped();
    signal_thread.finish();
    let carrier_result =
        carrier_result.map_err(|error| format!("ublk live device failed: {error}"));
    drop(backend);
    drop(runtime);
    let export_result = import_owner
        .export()
        .map_err(|error| format!("export Pool after block attach: {error}"));
    let completion = match (&carrier_result, &export_result) {
        (Ok(_), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error.clone()),
        (Err(error), Err(export_error)) => Err(format!("{error}; additionally {export_error}")),
    };
    live_owner.complete_export(completion);
    live_owner.stop();
    match (carrier_result, export_result) {
        (Ok(report), Ok(())) => {
            report.print();
            Ok(())
        }
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(export_error)) => Err(format!("{error}; additionally {export_error}")),
    }
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

fn combine_export_error(
    error: String,
    export: Result<(), tidefs_pool_import::ImportError>,
) -> String {
    match export {
        Ok(()) => error,
        Err(export_error) => format!("{error}; additionally failed to export Pool: {export_error}"),
    }
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

#[cfg(test)]
mod block_path_tests {
    use super::*;

    #[test]
    fn block_attach_requires_named_volume_target() {
        let result = handle_attach("mypool", &[], 4, 64, 30);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("<pool>/<name>"));
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
