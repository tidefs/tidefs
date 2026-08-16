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

#[cfg(feature = "cluster")]
use super::cluster_lease::{
    load_cluster_node_credential, load_cluster_public_identity, TransportPoolLeaseSession,
};
#[cfg(feature = "cluster")]
use tidefs_cluster::{ClusterLeaseGrant, ClusterLeaseSession};

#[cfg(feature = "cluster")]
#[derive(Debug)]
struct PendingClusterLease {
    grant: ClusterLeaseGrant,
    session: Box<dyn ClusterLeaseSession>,
}

#[cfg(feature = "cluster")]
impl PendingClusterLease {
    fn release(&mut self) -> Result<(), String> {
        self.session.release(&self.grant.token)
    }

    fn into_parts(self) -> (ClusterLeaseGrant, Box<dyn ClusterLeaseSession>) {
        (self.grant, self.session)
    }
}

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

        /// Acquire and maintain authenticated clustered Pool ownership.
        #[cfg(feature = "cluster")]
        #[arg(long, default_value_t = false, requires = "devices")]
        cluster: bool,

        /// Transport address of the Pool lease authority.
        #[cfg(feature = "cluster")]
        #[arg(long, requires = "cluster", required_if_eq("cluster", "true"))]
        cluster_authority_addr: Option<String>,

        /// Host-local private credential for this block owner node.
        #[cfg(feature = "cluster")]
        #[arg(
            long,
            value_name = "PATH",
            requires = "cluster",
            required_if_eq("cluster", "true")
        )]
        cluster_node_credential: Option<PathBuf>,

        /// Exact public identity trusted as Pool lease authority.
        #[cfg(feature = "cluster")]
        #[arg(
            long,
            value_name = "PATH",
            requires = "cluster",
            required_if_eq("cluster", "true")
        )]
        cluster_trusted_authority_identity: Option<PathBuf>,
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
            #[cfg(feature = "cluster")]
            cluster,
            #[cfg(feature = "cluster")]
            cluster_authority_addr,
            #[cfg(feature = "cluster")]
            cluster_node_credential,
            #[cfg(feature = "cluster")]
            cluster_trusted_authority_identity,
        } => {
            if let Err(err) = handle_attach(
                &target,
                &devices,
                nr_hw_queues,
                queue_depth,
                drain_deadline_secs,
                #[cfg(feature = "cluster")]
                cluster,
                #[cfg(feature = "cluster")]
                cluster_authority_addr.as_deref(),
                #[cfg(feature = "cluster")]
                cluster_node_credential.as_deref(),
                #[cfg(feature = "cluster")]
                cluster_trusted_authority_identity.as_deref(),
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
    #[cfg(feature = "cluster")] cluster: bool,
    #[cfg(feature = "cluster")] cluster_authority_addr: Option<&str>,
    #[cfg(feature = "cluster")] cluster_node_credential: Option<&Path>,
    #[cfg(feature = "cluster")] cluster_trusted_authority_identity: Option<&Path>,
) -> Result<(), String> {
    let _guard = super::authz::require_local_only("block attach");
    let target = crate::parser::parse_dataset_target(raw_target)?;

    #[cfg(feature = "cluster")]
    {
        if cluster && devices.is_empty() {
            return Err("--cluster requires explicit --devices Pool media".to_string());
        }
        if cluster && cluster_authority_addr.is_none() {
            return Err("--cluster requires --cluster-authority-addr".to_string());
        }
        if cluster && cluster_node_credential.is_none() {
            return Err("--cluster requires --cluster-node-credential".to_string());
        }
        if cluster && cluster_trusted_authority_identity.is_none() {
            return Err("--cluster requires --cluster-trusted-authority-identity".to_string());
        }
        if !cluster
            && (cluster_authority_addr.is_some()
                || cluster_node_credential.is_some()
                || cluster_trusted_authority_identity.is_some())
        {
            return Err("cluster trust inputs require --cluster".to_string());
        }
    }

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
    #[cfg(feature = "cluster")]
    if !cluster {
        super::live_owner::route_or_refuse_active_for_uuid_with_args(
            "block",
            "attach",
            &target.pool,
            config.pool_uuid,
            config.state == tidefs_types_pool_label_core::PoolState::Active,
            live_args,
        );
    }
    #[cfg(not(feature = "cluster"))]
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

    #[cfg(feature = "cluster")]
    let mut pending_cluster_lease = if cluster {
        Some(acquire_clustered_block_lease(
            devices,
            config.pool_uuid,
            cluster_authority_addr
                .ok_or_else(|| "--cluster requires --cluster-authority-addr".to_string())?,
            cluster_node_credential
                .ok_or_else(|| "--cluster requires --cluster-node-credential".to_string())?,
            cluster_trusted_authority_identity.ok_or_else(|| {
                "--cluster requires --cluster-trusted-authority-identity".to_string()
            })?,
        )?)
    } else {
        None
    };

    let lock_dir = PathBuf::from("/run/tidefs/import");
    let import_owner = match tidefs_pool_import::pool_import_owned(devices, &lock_dir, false, None)
    {
        Ok(owner) => owner,
        Err(error) => {
            let mut error = format!("import Pool: {error}");
            #[cfg(feature = "cluster")]
            if let Some(lease) = pending_cluster_lease.as_mut() {
                error = append_lease_release_error(error, lease.release());
            }
            return Err(error);
        }
    };
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
            let mut error = format!("open canonical Pool runtime: {error}");
            #[cfg(feature = "cluster")]
            if let Some(lease) = pending_cluster_lease.as_mut() {
                error = append_lease_release_error(error, lease.release());
            }
            return Err(combine_export_error(error, import_owner.export()));
        }
    };
    let runtime = SharedPoolRuntime::new(std::sync::Mutex::new(runtime));
    #[cfg(feature = "cluster")]
    let backend_result = match pending_cluster_lease.take() {
        Some(lease) => {
            let (grant, session) = lease.into_parts();
            PoolVolumeBackend::open_renewable_clustered_shared(
                Arc::clone(&runtime),
                &target.dataset,
                false,
                grant,
                session,
            )
        }
        None => PoolVolumeBackend::open_shared(Arc::clone(&runtime), &target.dataset, false),
    };
    #[cfg(not(feature = "cluster"))]
    let backend_result =
        PoolVolumeBackend::open_shared(Arc::clone(&runtime), &target.dataset, false);
    let mut backend = match backend_result {
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
                #[cfg(feature = "cluster")]
                let lease_release = if cluster {
                    backend
                        .release_clustered_authority()
                        .map_err(|error| error.to_string())
                } else {
                    Ok(())
                };
                #[cfg(not(feature = "cluster"))]
                let lease_release: Result<(), String> = Ok(());
                drop(backend);
                drop(runtime);
                return Err(combine_export_error(
                    append_lease_release_error(error, lease_release),
                    import_owner.export(),
                ));
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
            #[cfg(feature = "cluster")]
            let lease_release = if cluster {
                backend
                    .release_clustered_authority()
                    .map_err(|error| error.to_string())
            } else {
                Ok(())
            };
            #[cfg(not(feature = "cluster"))]
            let lease_release: Result<(), String> = Ok(());
            drop(backend);
            drop(runtime);
            return Err(combine_export_error(
                append_lease_release_error(
                    format!("start ublk live owner: {error}"),
                    lease_release,
                ),
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
    signal_thread.finish();
    let carrier_result =
        carrier_result.map_err(|error| format!("ublk live device failed: {error}"));
    live_owner.standalone_block_carrier_stopped(
        carrier_result
            .as_ref()
            .map(|_| ())
            .map_err(|error| error.clone()),
    );
    #[cfg(feature = "cluster")]
    let lease_release_result = if cluster {
        backend
            .release_clustered_authority()
            .map_err(|error| error.to_string())
    } else {
        Ok(())
    };
    #[cfg(not(feature = "cluster"))]
    let lease_release_result: Result<(), String> = Ok(());
    drop(backend);
    drop(runtime);
    let export_result = import_owner
        .export()
        .map_err(|error| format!("export Pool after block attach: {error}"));
    let mut completion_errors = Vec::new();
    if let Err(error) = &carrier_result {
        completion_errors.push(error.clone());
    }
    if let Err(error) = &lease_release_result {
        completion_errors.push(error.clone());
    }
    if let Err(error) = &export_result {
        completion_errors.push(error.clone());
    }
    let completion = if completion_errors.is_empty() {
        Ok(())
    } else {
        Err(completion_errors.join("; additionally "))
    };
    live_owner.complete_export(completion);
    live_owner.stop();
    if completion_errors.is_empty() {
        carrier_result
            .expect("successful completion retained ublk report")
            .print();
        Ok(())
    } else {
        Err(completion_errors.join("; additionally "))
    }
}

#[cfg(feature = "cluster")]
fn acquire_clustered_block_lease(
    devices: &[PathBuf],
    pool_guid: [u8; 16],
    authority_addr: &str,
    node_credential: &Path,
    trusted_authority_identity: &Path,
) -> Result<PendingClusterLease, String> {
    let local_credential = load_cluster_node_credential(node_credential)?;
    let trusted_authority_identity = load_cluster_public_identity(trusted_authority_identity)?;
    let authority_addr = authority_addr
        .parse()
        .map_err(|error| format!("invalid --cluster-authority-addr: {error}"))?;
    let mut session = TransportPoolLeaseSession::connect(
        authority_addr,
        pool_guid,
        &local_credential,
        &trusted_authority_identity,
    )?;
    let grant = session
        .acquire()
        .map_err(|error| format!("Pool lease acquire failed: {error}"))?;
    if grant.token.node_id != local_credential.node_id() || grant.token.pool_guid != pool_guid {
        let release_error = ClusterLeaseSession::release(&mut session, &grant.token).err();
        return Err(format!(
            "authority returned a Pool lease for the wrong owner or Pool{}",
            release_error
                .map(|error| format!("; release also failed: {error}"))
                .unwrap_or_default()
        ));
    }
    if let Err(error) =
        tidefs_local_object_store::pool_importer::PoolImporter::import_pool_clustered(
            devices,
            Some(pool_guid),
            Some(grant.token.clone()),
            Some(grant.valid_until),
        )
    {
        let release_error = ClusterLeaseSession::release(&mut session, &grant.token).err();
        return Err(format!(
            "clustered Pool import validation failed: {error}{}",
            release_error
                .map(|error| format!("; release also failed: {error}"))
                .unwrap_or_default()
        ));
    }
    Ok(PendingClusterLease {
        grant,
        session: Box::new(session),
    })
}

fn append_lease_release_error(error: String, release: Result<(), String>) -> String {
    match release {
        Ok(()) => error,
        Err(release_error) => {
            format!("{error}; additionally failed to release clustered Pool lease: {release_error}")
        }
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
        let result = handle_attach(
            "mypool",
            &[],
            4,
            64,
            30,
            #[cfg(feature = "cluster")]
            false,
            #[cfg(feature = "cluster")]
            None,
            #[cfg(feature = "cluster")]
            None,
            #[cfg(feature = "cluster")]
            None,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("<pool>/<name>"));
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cluster_block_attach_refuses_trust_inputs_without_cluster_mode() {
        let result = handle_attach(
            "mypool/vol",
            &[],
            1,
            64,
            30,
            false,
            Some("127.0.0.1:7411"),
            Some(Path::new("/unused/owner.credential")),
            Some(Path::new("/unused/authority.identity")),
        );
        assert!(result.unwrap_err().contains("require --cluster"));
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cluster_block_attach_refuses_missing_trust_before_pool_work() {
        let result = handle_attach(
            "mypool/vol",
            &[PathBuf::from("/unused/pool-device")],
            1,
            64,
            30,
            true,
            None,
            None,
            None,
        );
        assert!(result.unwrap_err().contains("--cluster-authority-addr"));
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
