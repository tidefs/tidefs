// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Userspace live-pool owner endpoint.
//!
//! This is the FUSE-session side of the imported-pool authority boundary:
//! pool-name commands talk to the runtime that owns cached state instead of
//! reopening devices or metadata directories behind it.
//! When a client knows the pool UUID, the request carries it and this owner
//! must prove the UUID matches before serving live cached state.

use std::fs;
#[cfg(feature = "block-volume")]
use std::io::Read;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "block-volume")]
use tidefs_block_volume_adapter_daemon::storage_backend::{
    PoolVolumeBackend, PoolVolumeSnapshotSummary, SharedPoolRuntime,
};
#[cfg(feature = "block-volume")]
use tidefs_block_volume_adapter_daemon::ublk_control_open::run_ublk_live_device;
#[cfg(feature = "block-volume")]
use tidefs_local_filesystem::vfs_engine_impl::SharedLocalFileSystem;
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminError,
    LivePoolAdminRequest, LivePoolAdminResponse, VfsEngineStatFs, LIVE_POOL_ADMIN_PROTOCOL_VERSION,
};
#[cfg(test)]
use tidefs_vfs_engine::{LivePoolAdminErrorKind, LivePoolAdminOutput, LivePoolAdminResponseBody};

pub type LiveOwnerEngine = Arc<Mutex<Box<dyn VfsEngineStatFs + Send>>>;

#[derive(Clone)]
enum LiveOwnerAdmin {
    Fuse {
        engine: LiveOwnerEngine,
        #[cfg(feature = "block-volume")]
        filesystem: SharedLocalFileSystem,
    },
    #[cfg(feature = "block-volume")]
    StandaloneBlock { runtime: SharedPoolRuntime },
}

#[derive(Clone, Debug)]
pub struct LiveOwnerConfig {
    pub pool_name: String,
    pub pool_uuid: [u8; 16],
    pub backing_dir: PathBuf,
    pub mountpoint: PathBuf,
    pub runtime_dir: PathBuf,
    pub read_only: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LiveOwnerManifest {
    pub protocol: String,
    pub owner_kind: String,
    pub pool_name: String,
    pub pool_uuid: String,
    pub pid: u32,
    pub backing_dir: String,
    pub mountpoint: String,
    pub socket_path: String,
    pub read_only: bool,
}

pub struct LiveOwnerHandle {
    shutdown: Arc<AtomicBool>,
    #[cfg(feature = "block-volume")]
    block_export: Arc<Mutex<Option<ActiveBlockExport>>>,
    join: Option<JoinHandle<()>>,
    socket_path: PathBuf,
    manifest_path: PathBuf,
}

impl LiveOwnerHandle {
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        #[cfg(feature = "block-volume")]
        stop_active_block_export(&self.block_export);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        cleanup_endpoint(&self.socket_path, &self.manifest_path);
    }
}

impl Drop for LiveOwnerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        #[cfg(feature = "block-volume")]
        stop_active_block_export(&self.block_export);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        cleanup_endpoint(&self.socket_path, &self.manifest_path);
    }
}

pub fn start_fuse_owner(
    config: LiveOwnerConfig,
    engine: LiveOwnerEngine,
    #[cfg(feature = "block-volume")] filesystem: SharedLocalFileSystem,
    shutdown: Arc<AtomicBool>,
) -> Result<LiveOwnerHandle, String> {
    start_owner(
        config,
        "fuse",
        LiveOwnerAdmin::Fuse {
            engine,
            #[cfg(feature = "block-volume")]
            filesystem,
        },
        None,
        shutdown,
    )
}

/// Start the existing live-owner protocol for a standalone ublk Pool owner.
///
/// The supplied runtime is the same neutral owner used by the block backend;
/// `active_volume` seeds export admission for the lifetime of the carrier.
#[cfg(feature = "block-volume")]
pub fn start_block_owner(
    config: LiveOwnerConfig,
    runtime: SharedPoolRuntime,
    active_volume: String,
    shutdown: Arc<AtomicBool>,
) -> Result<LiveOwnerHandle, String> {
    start_owner(
        config,
        "ublk",
        LiveOwnerAdmin::StandaloneBlock { runtime },
        Some(active_volume),
        shutdown,
    )
}

fn start_owner(
    config: LiveOwnerConfig,
    owner_kind: &str,
    admin: LiveOwnerAdmin,
    #[cfg(feature = "block-volume")] active_volume: Option<String>,
    #[cfg(not(feature = "block-volume"))] _active_volume: Option<String>,
    shutdown: Arc<AtomicBool>,
) -> Result<LiveOwnerHandle, String> {
    fs::create_dir_all(&config.runtime_dir).map_err(|err| {
        format!(
            "create live owner runtime dir {}: {err}",
            config.runtime_dir.display()
        )
    })?;

    let socket_path = config.runtime_dir.join("owner.sock");
    let manifest_path = config.runtime_dir.join("owner.json");
    prepare_socket_path(&socket_path)?;

    let listener = UnixListener::bind(&socket_path)
        .map_err(|err| format!("bind live owner socket {}: {err}", socket_path.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("set nonblocking live owner socket: {err}"))?;
    let _ = fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660));

    let manifest = LiveOwnerManifest {
        protocol: "tidefs-live-owner-admin-v1".to_string(),
        owner_kind: owner_kind.to_string(),
        pool_name: config.pool_name.clone(),
        pool_uuid: hex_uuid(&config.pool_uuid),
        pid: std::process::id(),
        backing_dir: fs::canonicalize(&config.backing_dir)
            .unwrap_or_else(|_| config.backing_dir.clone())
            .display()
            .to_string(),
        mountpoint: config.mountpoint.display().to_string(),
        socket_path: socket_path.display().to_string(),
        read_only: config.read_only,
    };
    write_manifest(&manifest_path, &manifest)?;

    let thread_manifest = manifest.clone();
    let thread_shutdown = Arc::clone(&shutdown);
    #[cfg(feature = "block-volume")]
    let block_export = Arc::new(Mutex::new(active_volume.map(|volume| ActiveBlockExport {
        volume,
        shutdown: Arc::clone(&shutdown),
    })));
    #[cfg(feature = "block-volume")]
    let thread_block_export = Arc::clone(&block_export);
    let join = thread::spawn(move || {
        let mut clients = Vec::<JoinHandle<()>>::new();
        while !thread_shutdown.load(Ordering::Acquire) {
            reap_finished_clients(&mut clients);
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let manifest = thread_manifest.clone();
                    let admin = admin.clone();
                    let shutdown = Arc::clone(&thread_shutdown);
                    #[cfg(feature = "block-volume")]
                    let block_export = Arc::clone(&thread_block_export);
                    let client = thread::spawn(move || {
                        handle_client(
                            stream,
                            &manifest,
                            &admin,
                            #[cfg(feature = "block-volume")]
                            &block_export,
                            &shutdown,
                        );
                    });
                    clients.push(client);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    eprintln!("tidefs live owner: accept failed: {err}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        }
        #[cfg(feature = "block-volume")]
        stop_active_block_export(&thread_block_export);
        for client in clients.drain(..) {
            let _ = client.join();
        }
    });

    Ok(LiveOwnerHandle {
        shutdown,
        #[cfg(feature = "block-volume")]
        block_export,
        join: Some(join),
        socket_path,
        manifest_path,
    })
}

fn reap_finished_clients(clients: &mut Vec<JoinHandle<()>>) {
    let mut index = 0;
    while index < clients.len() {
        if clients[index].is_finished() {
            let client = clients.swap_remove(index);
            let _ = client.join();
        } else {
            index += 1;
        }
    }
}

fn prepare_socket_path(path: &Path) -> Result<(), String> {
    match UnixStream::connect(path) {
        Ok(_) => Err(format!(
            "live owner socket {} already has a listener",
            path.display()
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => {
            let _ = fs::remove_file(path);
            Ok(())
        }
    }
}

fn write_manifest(path: &Path, manifest: &LiveOwnerManifest) -> Result<(), String> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(manifest)
        .map_err(|err| format!("encode live owner manifest: {err}"))?;
    fs::write(&tmp, bytes)
        .map_err(|err| format!("write live owner manifest {}: {err}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|err| format!("publish live owner manifest {}: {err}", path.display()))
}

fn cleanup_endpoint(socket_path: &Path, manifest_path: &Path) {
    let _ = fs::remove_file(socket_path);
    let _ = fs::remove_file(manifest_path);
}

fn handle_client(
    stream: UnixStream,
    manifest: &LiveOwnerManifest,
    admin: &LiveOwnerAdmin,
    #[cfg(feature = "block-volume")] block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    shutdown: &Arc<AtomicBool>,
) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    #[cfg(feature = "block-volume")]
    let disconnect_monitor = stream.try_clone().ok();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let response = match reader.read_line(&mut line) {
        Ok(0) => live_admin_malformed("empty live-owner request"),
        Ok(_) => match decode_live_pool_admin_request(&line) {
            Ok(request) => dispatch_request(
                request,
                manifest,
                admin,
                #[cfg(feature = "block-volume")]
                block_export,
                #[cfg(feature = "block-volume")]
                disconnect_monitor,
                shutdown,
            ),
            Err(err) => live_admin_typed_error(err),
        },
        Err(err) => live_admin_malformed(format!("read live-owner request: {err}")),
    };

    let mut stream = reader.into_inner();
    match serde_json::to_vec(&response) {
        Ok(mut out) => {
            out.push(b'\n');
            let _ = stream.write_all(&out);
        }
        Err(err) => {
            let _ = writeln!(
                stream,
                "{{\"version\":{},\"exit_code\":2,\"body\":{{\"kind\":\"error\",\"value\":{{\"message\":\"encode response: {err}\",\"machine_json\":null}}}}}}",
                LIVE_POOL_ADMIN_PROTOCOL_VERSION
            );
        }
    }
}

fn decode_live_pool_admin_request(line: &str) -> Result<LivePoolAdminRequest, LivePoolAdminError> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|err| {
        LivePoolAdminError::malformed(format!("decode live-owner request: {err}"))
    })?;

    let version = decode_live_pool_admin_version(&value)?;
    reject_unsupported_live_pool_admin_version(version)?;

    if let Some(command) = value
        .get("command")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_wire_command_parts)
    {
        LivePoolAdminCommand::from_parts(command.0, &command.1)?;
    }

    serde_json::from_value::<LivePoolAdminRequest>(value)
        .map_err(|err| LivePoolAdminError::malformed(format!("decode live-owner request: {err}")))
}

fn decode_live_pool_admin_version(value: &serde_json::Value) -> Result<u16, LivePoolAdminError> {
    let Some(version) = value.get("version") else {
        return Err(LivePoolAdminError::malformed(
            "decode live-owner request: missing version",
        ));
    };

    let Some(version) = version
        .as_u64()
        .and_then(|version| u16::try_from(version).ok())
    else {
        return Err(LivePoolAdminError::malformed(
            "decode live-owner request: malformed version",
        ));
    };

    Ok(version)
}

fn reject_unsupported_live_pool_admin_version(version: u16) -> Result<(), LivePoolAdminError> {
    if version != LIVE_POOL_ADMIN_PROTOCOL_VERSION {
        return Err(LivePoolAdminError::unsupported_version(version));
    }

    Ok(())
}

fn parse_wire_command_parts(command: &str) -> Option<(&str, String)> {
    let (command, operation) = command.split_once('_')?;
    Some((command, operation.replace('_', "-")))
}

fn dispatch_request(
    request: LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
    admin: &LiveOwnerAdmin,
    #[cfg(feature = "block-volume")] block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    #[cfg(feature = "block-volume")] disconnect_monitor: Option<UnixStream>,
    shutdown: &Arc<AtomicBool>,
) -> LivePoolAdminResponse {
    if let Err(err) = request.validate_version() {
        return live_admin_typed_error(err);
    }
    if let Err(response) = validate_request_pool_identity(&request, manifest) {
        return response;
    }

    match request.command {
        LivePoolAdminCommand::PoolStatus => pool_status(&request, manifest, admin),
        LivePoolAdminCommand::PoolImport => already_owned(&request, "import", manifest),
        LivePoolAdminCommand::PoolMount => pool_mount_refused(&request, manifest),
        LivePoolAdminCommand::PoolExport => pool_export(
            &request,
            manifest,
            #[cfg(feature = "block-volume")]
            block_export,
            shutdown,
        ),
        LivePoolAdminCommand::PoolDestroy => pool_destroy_refused(&request, manifest),
        #[cfg(feature = "block-volume")]
        LivePoolAdminCommand::DatasetResize
        | LivePoolAdminCommand::DatasetRename
        | LivePoolAdminCommand::DatasetDestroy
        | LivePoolAdminCommand::SnapshotCreate
        | LivePoolAdminCommand::SnapshotDestroy
        | LivePoolAdminCommand::SnapshotRollback => {
            volume_lifecycle_mutation(&request, admin, block_export)
        }
        #[cfg(not(feature = "block-volume"))]
        LivePoolAdminCommand::DatasetResize
        | LivePoolAdminCommand::DatasetRename
        | LivePoolAdminCommand::DatasetDestroy
        | LivePoolAdminCommand::SnapshotCreate
        | LivePoolAdminCommand::SnapshotDestroy
        | LivePoolAdminCommand::SnapshotRollback => delegate_admin_request(&request, admin),
        LivePoolAdminCommand::PoolGet
        | LivePoolAdminCommand::PoolSet
        | LivePoolAdminCommand::PoolListProps
        | LivePoolAdminCommand::PoolIntegrityCheck
        | LivePoolAdminCommand::DatasetCreate
        | LivePoolAdminCommand::DatasetList
        | LivePoolAdminCommand::DatasetSetStrategy
        | LivePoolAdminCommand::DatasetUpgrade
        | LivePoolAdminCommand::DatasetGet
        | LivePoolAdminCommand::DatasetSet
        | LivePoolAdminCommand::DatasetListProps
        | LivePoolAdminCommand::DatasetSealKey
        | LivePoolAdminCommand::DatasetRotateKey
        | LivePoolAdminCommand::SnapshotList
        | LivePoolAdminCommand::SnapshotExtract
        | LivePoolAdminCommand::SnapshotSend
        | LivePoolAdminCommand::PerformanceAdmissionSnapshot
        | LivePoolAdminCommand::DeviceStatus
        | LivePoolAdminCommand::DeviceRemove => delegate_admin_request(&request, admin),
        #[cfg(feature = "block-volume")]
        LivePoolAdminCommand::BlockAttach => match admin {
            LiveOwnerAdmin::Fuse { filesystem, .. } => block_attach(
                &request,
                manifest,
                filesystem,
                block_export,
                disconnect_monitor,
                shutdown,
            ),
            LiveOwnerAdmin::StandaloneBlock { .. } => {
                let volume = request_arg_str(&request.args, "volume")
                    .ok()
                    .flatten()
                    .unwrap_or("<unknown>");
                LivePoolAdminResponse::error(
                    1,
                    format!(
                        "pool '{}' already has standalone ublk volume '{}' actively exported",
                        manifest.pool_name, volume
                    ),
                )
            }
        },
        #[cfg(not(feature = "block-volume"))]
        LivePoolAdminCommand::BlockAttach => unsupported_admin_command_response(&request),
    }
}

#[cfg(feature = "block-volume")]
#[derive(Clone)]
struct ActiveBlockExport {
    volume: String,
    shutdown: Arc<AtomicBool>,
}

#[cfg(feature = "block-volume")]
fn volume_lifecycle_mutation(
    request: &LivePoolAdminRequest,
    admin: &LiveOwnerAdmin,
    block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
) -> LivePoolAdminResponse {
    let target = match volume_mutation_target(request) {
        Ok(target) => target,
        Err(error) => return live_admin_typed_error(error),
    };
    let Some(target) = target else {
        return delegate_admin_request(request, admin);
    };
    match with_volume_mutation_admission(block_export, target, || {
        delegate_admin_request(request, admin)
    }) {
        Ok(response) => response,
        Err(message) => {
            let (command, operation) = request.command.parts();
            LivePoolAdminResponse::error(1, format!("{command} {operation} refused: {message}"))
        }
    }
}

#[cfg(feature = "block-volume")]
fn with_volume_mutation_admission<T>(
    block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    target: &str,
    mutation: impl FnOnce() -> T,
) -> Result<T, String> {
    let export_admission = block_export
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    ensure_volume_mutation_allowed(&export_admission, target)?;
    let result = mutation();
    drop(export_admission);
    Ok(result)
}

#[cfg(feature = "block-volume")]
fn ensure_volume_mutation_allowed(
    active: &Option<ActiveBlockExport>,
    target: &str,
) -> Result<(), String> {
    if active
        .as_ref()
        .is_some_and(|export| export.volume == target)
    {
        return Err(format!(
            "volume '{target}' is actively exported by this live owner; close the block export before mutation"
        ));
    }
    Ok(())
}

#[cfg(feature = "block-volume")]
fn volume_mutation_target(
    request: &LivePoolAdminRequest,
) -> Result<Option<&str>, LivePoolAdminError> {
    let name = match request.command {
        LivePoolAdminCommand::DatasetResize | LivePoolAdminCommand::DatasetDestroy => "name",
        LivePoolAdminCommand::DatasetRename => "old_name",
        LivePoolAdminCommand::SnapshotCreate
        | LivePoolAdminCommand::SnapshotDestroy
        | LivePoolAdminCommand::SnapshotRollback => "target",
        _ => {
            return Err(LivePoolAdminError::malformed(
                "live-owner volume mutation has no target",
            ))
        }
    };
    let target = request_arg_str(&request.args, name)?;
    if matches!(
        request.command,
        LivePoolAdminCommand::SnapshotCreate
            | LivePoolAdminCommand::SnapshotDestroy
            | LivePoolAdminCommand::SnapshotRollback
    ) && target.is_none()
    {
        return Ok(None);
    }
    let target = target.ok_or_else(|| {
        LivePoolAdminError::malformed(format!("dataset mutation requires {name}"))
    })?;
    if matches!(
        request.command,
        LivePoolAdminCommand::SnapshotCreate
            | LivePoolAdminCommand::SnapshotDestroy
            | LivePoolAdminCommand::SnapshotRollback
    ) {
        let (source, snapshot) = target.rsplit_once('@').ok_or_else(|| {
            LivePoolAdminError::malformed("volume snapshot target requires <dataset>@<snapshot>")
        })?;
        if source.is_empty() || snapshot.is_empty() || source.contains('@') {
            return Err(LivePoolAdminError::malformed(
                "volume snapshot target must name one source and one snapshot",
            ));
        }
        return Ok(Some(source));
    }
    Ok(Some(target))
}

#[cfg(feature = "block-volume")]
fn stop_active_block_export(block_export: &Arc<Mutex<Option<ActiveBlockExport>>>) {
    if let Some(active) = block_export
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .as_ref()
    {
        active.shutdown.store(true, Ordering::Release);
    }
}

#[cfg(feature = "block-volume")]
fn reserve_block_export(
    block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    owner_shutdown: &Arc<AtomicBool>,
    pool: &str,
    volume: &str,
    export_shutdown: &Arc<AtomicBool>,
) -> Result<(), String> {
    let mut active = block_export
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if owner_shutdown.load(Ordering::Acquire) {
        return Err("live owner is shutting down".to_string());
    }
    if let Some(existing) = active.as_ref() {
        return Err(format!(
            "pool '{pool}' already exports volume '{}'; concurrent block exports are refused",
            existing.volume
        ));
    }
    *active = Some(ActiveBlockExport {
        volume: volume.to_string(),
        shutdown: Arc::clone(export_shutdown),
    });
    Ok(())
}

#[cfg(feature = "block-volume")]
fn clear_block_export(
    block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    volume: &str,
    export_shutdown: &Arc<AtomicBool>,
) {
    let mut active = block_export
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if active.as_ref().is_some_and(|current| {
        current.volume == volume && Arc::ptr_eq(&current.shutdown, export_shutdown)
    }) {
        *active = None;
    }
}

#[cfg(feature = "block-volume")]
fn block_attach(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
    filesystem: &SharedLocalFileSystem,
    block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    disconnect_monitor: Option<UnixStream>,
    owner_shutdown: &Arc<AtomicBool>,
) -> LivePoolAdminResponse {
    let (volume, nr_hw_queues, queue_depth, drain_deadline_secs) =
        match block_attach_request_args(&request.args) {
            Ok(args) => args,
            Err(err) => return live_admin_typed_error(err),
        };
    if owner_shutdown.load(Ordering::Acquire) {
        return LivePoolAdminResponse::error(1, "live owner is shutting down");
    }

    let export_shutdown = Arc::new(AtomicBool::new(false));
    if let Err(message) = reserve_block_export(
        block_export,
        owner_shutdown,
        &manifest.pool_name,
        volume,
        &export_shutdown,
    ) {
        return LivePoolAdminResponse::error(1, message);
    }
    let mut backend =
        match PoolVolumeBackend::open_mounted(filesystem.clone(), volume, manifest.read_only) {
            Ok(backend) => backend,
            Err(err) => {
                clear_block_export(block_export, volume, &export_shutdown);
                return LivePoolAdminResponse::error(
                    1,
                    format!("open Pool volume '{volume}' for block export: {err}"),
                );
            }
        };
    if owner_shutdown.load(Ordering::Acquire) {
        clear_block_export(block_export, volume, &export_shutdown);
        return LivePoolAdminResponse::error(1, "live owner is shutting down");
    }

    let disconnect_stop = Arc::new(AtomicBool::new(false));
    let disconnect_join = disconnect_monitor.map(|stream| {
        monitor_client_disconnect(
            stream,
            Arc::clone(&disconnect_stop),
            Arc::clone(&export_shutdown),
        )
    });

    let result = run_ublk_live_device(
        None,
        &mut backend,
        Arc::clone(&export_shutdown),
        false,
        nr_hw_queues,
        queue_depth,
        drain_deadline_secs,
    );
    disconnect_stop.store(true, Ordering::Release);
    if let Some(join) = disconnect_join {
        let _ = join.join();
    }
    clear_block_export(block_export, volume, &export_shutdown);

    match result {
        Ok(_) => LivePoolAdminResponse::ok_text(format!(
            "block export stopped: {}/{}",
            manifest.pool_name, volume
        )),
        Err(err) => LivePoolAdminResponse::error(
            1,
            format!(
                "block export failed for {}/{}: {err}",
                manifest.pool_name, volume
            ),
        ),
    }
}

#[cfg(feature = "block-volume")]
fn monitor_client_disconnect(
    mut stream: UnixStream,
    stop: Arc<AtomicBool>,
    export_shutdown: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
        let mut byte = [0_u8; 1];
        while !stop.load(Ordering::Acquire) {
            match stream.read(&mut byte) {
                Ok(0) => {
                    export_shutdown.store(true, Ordering::Release);
                    break;
                }
                Ok(_) => {
                    export_shutdown.store(true, Ordering::Release);
                    break;
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => {
                    export_shutdown.store(true, Ordering::Release);
                    break;
                }
            }
        }
    })
}

#[cfg(feature = "block-volume")]
fn block_attach_request_args(
    args: &LivePoolAdminArgs,
) -> Result<(&str, u16, u16, u64), LivePoolAdminError> {
    validate_request_arg_names(
        args,
        &[
            "volume",
            "nr_hw_queues",
            "queue_depth",
            "drain_deadline_secs",
        ],
    )?;
    let volume = request_arg_str(args, "volume")?
        .ok_or_else(|| LivePoolAdminError::malformed("block attach requires volume"))?;
    let nr_hw_queues = request_arg_u16(args, "nr_hw_queues")?.unwrap_or(1);
    let queue_depth = request_arg_u16(args, "queue_depth")?.unwrap_or(64);
    let drain_deadline_secs = request_arg_u64(args, "drain_deadline_secs")?.unwrap_or(30);
    Ok((volume, nr_hw_queues, queue_depth, drain_deadline_secs))
}

fn validate_request_pool_identity(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> Result<(), LivePoolAdminResponse> {
    if request.pool != manifest.pool_name {
        return Err(live_admin_malformed(format!(
            "live owner for pool '{}' cannot serve pool '{}'",
            manifest.pool_name, request.pool
        )));
    }
    if let Err(message) = validate_requested_pool_uuid(request.pool_uuid.as_deref(), manifest) {
        return Err(live_admin_malformed(message));
    }
    Ok(())
}

fn validate_requested_pool_uuid(
    requested_uuid: Option<&str>,
    manifest: &LiveOwnerManifest,
) -> Result<(), String> {
    let Some(requested_uuid) = requested_uuid else {
        return Ok(());
    };
    if requested_uuid.eq_ignore_ascii_case(&manifest.pool_uuid) {
        return Ok(());
    }
    Err(format!(
        "live owner for pool '{}' owns uuid {}, not requested uuid {}",
        manifest.pool_name, manifest.pool_uuid, requested_uuid
    ))
}

fn delegate_admin_request(
    request: &LivePoolAdminRequest,
    admin: &LiveOwnerAdmin,
) -> LivePoolAdminResponse {
    match admin {
        LiveOwnerAdmin::Fuse { engine, .. } => match engine.lock() {
            Ok(engine) => match engine.live_pool_admin_request(request) {
                Ok(response) => response,
                Err(_) => unsupported_admin_command_response(request),
            },
            Err(_) => LivePoolAdminResponse::error(1, "live owner engine lock poisoned"),
        },
        #[cfg(feature = "block-volume")]
        LiveOwnerAdmin::StandaloneBlock { runtime } => {
            standalone_block_admin_request(request, runtime)
        }
    }
}

#[cfg(feature = "block-volume")]
fn standalone_block_admin_request(
    request: &LivePoolAdminRequest,
    runtime: &SharedPoolRuntime,
) -> LivePoolAdminResponse {
    let mut runtime = match runtime.lock() {
        Ok(runtime) => runtime,
        Err(_) => return LivePoolAdminResponse::error(1, "shared Pool runtime lock poisoned"),
    };
    let wants_json = request.output.wants_json();
    match request.command {
        LivePoolAdminCommand::DatasetResize => {
            let name = match required_request_arg_str(&request.args, "name") {
                Ok(name) => name,
                Err(error) => return live_admin_typed_error(error),
            };
            let size = match request_arg_u64(&request.args, "size") {
                Ok(Some(size)) => size,
                Ok(None) => {
                    return live_admin_malformed("dataset resize requires size");
                }
                Err(error) => return live_admin_typed_error(error),
            };
            match runtime.resize_volume(name, size) {
                Ok(result) if wants_json => LivePoolAdminResponse::ok_machine_json(
                    json!({
                        "ok": true,
                        "operation": "resize",
                        "pool": request.pool,
                        "dataset": name,
                        "size": result.geometry.capacity_bytes,
                        "block_size": result.geometry.block_size_bytes,
                        "generation": result.generation,
                        "resize_generation": result.resize_generation,
                    })
                    .to_string(),
                ),
                Ok(result) => LivePoolAdminResponse::ok_text(format!(
                    "dataset '{name}' resized in imported pool '{}': size={} block_size={} generation={} resize_generation={}",
                    request.pool,
                    result.geometry.capacity_bytes,
                    result.geometry.block_size_bytes,
                    result.generation,
                    result.resize_generation,
                )),
                Err(error) => {
                    LivePoolAdminResponse::error(1, format!("dataset resize: {error}"))
                }
            }
        }
        LivePoolAdminCommand::DatasetRename => {
            let old_name = match required_request_arg_str(&request.args, "old_name") {
                Ok(name) => name,
                Err(error) => return live_admin_typed_error(error),
            };
            let new_name = match required_request_arg_str(&request.args, "new_name") {
                Ok(name) => name,
                Err(error) => return live_admin_typed_error(error),
            };
            match runtime.rename_dataset(old_name, new_name) {
                Ok(_) => LivePoolAdminResponse::ok_text(format!(
                    "dataset '{old_name}' renamed to '{new_name}' in imported pool '{}'",
                    request.pool
                )),
                Err(error) => LivePoolAdminResponse::error(
                    1,
                    format!(
                        "dataset rename: failed to rename '{old_name}' -> '{new_name}': {error}"
                    ),
                ),
            }
        }
        LivePoolAdminCommand::DatasetDestroy => {
            let name = match required_request_arg_str(&request.args, "name") {
                Ok(name) => name,
                Err(error) => return live_admin_typed_error(error),
            };
            match runtime.destroy_volume(name) {
                Ok(_) => LivePoolAdminResponse::ok_text(format!(
                    "dataset '{name}' logically destroyed; physical reclaim remains pending"
                )),
                Err(error) => LivePoolAdminResponse::error(1, format!("dataset destroy: {error}")),
            }
        }
        LivePoolAdminCommand::SnapshotCreate => standalone_volume_snapshot_response(
            "created",
            required_request_arg_str(&request.args, "target").and_then(|target| {
                runtime
                    .create_volume_snapshot(target)
                    .map_err(|error| LivePoolAdminError::malformed(error.to_string()))
            }),
            wants_json,
        ),
        LivePoolAdminCommand::SnapshotDestroy => standalone_volume_snapshot_response(
            "logically destroyed",
            required_request_arg_str(&request.args, "target").and_then(|target| {
                runtime
                    .destroy_volume_snapshot(target)
                    .map_err(|error| LivePoolAdminError::malformed(error.to_string()))
            }),
            wants_json,
        ),
        LivePoolAdminCommand::SnapshotRollback => {
            let target = match required_request_arg_str(&request.args, "target") {
                Ok(target) => target,
                Err(error) => return live_admin_typed_error(error),
            };
            match runtime.restore_volume_snapshot(target) {
                Ok(result) if wants_json => LivePoolAdminResponse::ok_machine_json(
                    json!({
                        "ok": true,
                        "outcome": "restored",
                        "snapshot": standalone_volume_snapshot_json(&result.snapshot),
                        "size": result.geometry.capacity_bytes,
                        "generation": result.generation,
                        "resize_generation": result.resize_generation,
                        "snapshot_generation": result.snapshot_generation,
                    })
                    .to_string(),
                ),
                Ok(result) => LivePoolAdminResponse::ok_text(format!(
                    "volume snapshot '{}' restored to '{}' (size={} generation={} resize_generation={} snapshot_generation={})",
                    result.snapshot.path,
                    result.snapshot.source_path,
                    result.geometry.capacity_bytes,
                    result.generation,
                    result.resize_generation,
                    result.snapshot_generation,
                )),
                Err(error) => {
                    LivePoolAdminResponse::error(1, format!("snapshot rollback: {error}"))
                }
            }
        }
        LivePoolAdminCommand::SnapshotList => match runtime.list_volume_snapshots() {
            Ok(snapshots) if wants_json => LivePoolAdminResponse::ok_machine_json(
                json!({
                    "snapshots": [],
                    "volume_snapshots": snapshots
                        .iter()
                        .map(standalone_volume_snapshot_json)
                        .collect::<Vec<_>>(),
                })
                .to_string(),
            ),
            Ok(snapshots) if snapshots.is_empty() => LivePoolAdminResponse::ok_text("no snapshots"),
            Ok(snapshots) => LivePoolAdminResponse::ok_text(
                snapshots
                    .iter()
                    .map(standalone_volume_snapshot_line)
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
            Err(error) => LivePoolAdminResponse::error(1, format!("snapshot list: {error}")),
        },
        _ => unsupported_admin_command_response(request),
    }
}

#[cfg(feature = "block-volume")]
fn required_request_arg_str<'a>(
    args: &'a LivePoolAdminArgs,
    name: &str,
) -> Result<&'a str, LivePoolAdminError> {
    request_arg_str(args, name)?
        .ok_or_else(|| LivePoolAdminError::malformed(format!("request requires {name}")))
}

#[cfg(feature = "block-volume")]
fn standalone_volume_snapshot_response(
    outcome: &str,
    result: Result<PoolVolumeSnapshotSummary, LivePoolAdminError>,
    wants_json: bool,
) -> LivePoolAdminResponse {
    match result {
        Ok(summary) if wants_json => LivePoolAdminResponse::ok_machine_json(
            json!({
                "ok": true,
                "outcome": outcome,
                "physical_reclaim": false,
                "snapshot": standalone_volume_snapshot_json(&summary),
            })
            .to_string(),
        ),
        Ok(summary) => {
            let mut text = format!("{} {outcome}", standalone_volume_snapshot_line(&summary));
            if outcome == "logically destroyed" {
                text.push_str(
                    "\nphysical reclaim remains pending; no secure-erasure claim is made",
                );
            }
            LivePoolAdminResponse::ok_text(text)
        }
        Err(error) => LivePoolAdminResponse::error(1, error.message),
    }
}

#[cfg(feature = "block-volume")]
fn standalone_volume_snapshot_line(summary: &PoolVolumeSnapshotSummary) -> String {
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

#[cfg(feature = "block-volume")]
fn standalone_volume_snapshot_json(summary: &PoolVolumeSnapshotSummary) -> serde_json::Value {
    json!({
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

fn unsupported_admin_command_response(request: &LivePoolAdminRequest) -> LivePoolAdminResponse {
    let (command, operation) = request.command.parts();
    live_admin_typed_error(LivePoolAdminError::unsupported_command(command, operation))
}

fn pool_status(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
    admin: &LiveOwnerAdmin,
) -> LivePoolAdminResponse {
    if let Err(err) = validate_request_arg_names(&request.args, &[]) {
        return live_admin_typed_error(err);
    }

    let ctx = RequestCtx {
        uid: 0,
        gid: 0,
        pid: 0,
        umask: 0,
        groups: vec![0],
    };
    let statfs = match admin {
        LiveOwnerAdmin::Fuse { engine, .. } => match engine.lock() {
            Ok(engine) => match engine.statfs(&ctx) {
                Ok(statfs) => statfs,
                Err(errno) => {
                    return LivePoolAdminResponse::error(
                        1,
                        format!("live owner statfs failed with {errno:?}"),
                    )
                }
            },
            Err(_) => return LivePoolAdminResponse::error(1, "live owner engine lock poisoned"),
        },
        #[cfg(feature = "block-volume")]
        LiveOwnerAdmin::StandaloneBlock { runtime } => match runtime.lock() {
            Ok(runtime) => {
                let stats = runtime.pool().pool_stats();
                let block_size = 4096_u64;
                let files =
                    u64::try_from(runtime.dataset_catalog().list_all().len()).unwrap_or(u64::MAX);
                tidefs_types_vfs_core::StatFs::new(
                    block_size as u32,
                    block_size as u32,
                    stats.total_capacity_bytes / block_size,
                    stats.available_bytes / block_size,
                    stats.available_bytes / block_size,
                    files,
                    u64::MAX.saturating_sub(files),
                    255,
                    0,
                    0,
                )
            }
            Err(_) => return LivePoolAdminResponse::error(1, "shared Pool runtime lock poisoned"),
        },
    };

    let value = json!({
        "pool_name": manifest.pool_name,
        "pool_uuid": manifest.pool_uuid,
        "state": "Active",
        "owner_kind": manifest.owner_kind,
        "pid": manifest.pid,
        "backing_dir": manifest.backing_dir,
        "mountpoint": manifest.mountpoint,
        "socket_path": manifest.socket_path,
        "statfs": {
            "block_size": statfs.block_size,
            "fragment_size": statfs.fragment_size,
            "total_blocks": statfs.total_blocks,
            "free_blocks": statfs.free_blocks,
            "avail_blocks": statfs.avail_blocks,
            "files": statfs.files,
            "files_free": statfs.files_free,
            "name_max": statfs.name_max,
            "fsid_hi": statfs.fsid_hi,
            "fsid_lo": statfs.fsid_lo,
        }
    });

    if request.output.wants_json() {
        LivePoolAdminResponse::ok_machine_json(value.to_string())
    } else {
        LivePoolAdminResponse::ok_text(format!(
            "pool: {}\n  pool uuid:   {}\n  state:       Active\n  owner:       {} (pid {})\n  backing dir: {}\n  mountpoint:  {}\n  blocks:      total={} free={} avail={}\n  files:       total={} free={}",
            manifest.pool_name,
            manifest.pool_uuid,
            manifest.owner_kind,
            manifest.pid,
            manifest.backing_dir,
            manifest.mountpoint,
            statfs.total_blocks,
            statfs.free_blocks,
            statfs.avail_blocks,
            statfs.files,
            statfs.files_free
        ))
    }
}

fn already_owned(
    request: &LivePoolAdminRequest,
    operation: &str,
    manifest: &LiveOwnerManifest,
) -> LivePoolAdminResponse {
    if let Err(err) = validate_pool_import_request_args(&request.args) {
        return live_admin_typed_error(err);
    }

    let value = json!({
        "pool_name": manifest.pool_name,
        "pool_uuid": manifest.pool_uuid,
        "state": "Active",
        "owner_kind": manifest.owner_kind,
        "pid": manifest.pid,
        "backing_dir": manifest.backing_dir,
        "mountpoint": manifest.mountpoint,
        "operation": operation,
        "already_owned": true,
    });
    if request.output.wants_json() {
        LivePoolAdminResponse::ok_machine_json(value.to_string())
    } else {
        LivePoolAdminResponse::ok_text(format!(
            "pool already imported: {}\n  owner:      {} (pid {})\n  mountpoint: {}",
            manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
        ))
    }
}

fn pool_mount_refused(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> LivePoolAdminResponse {
    let (mountpoint, dataset, read_only, relatime) = match pool_mount_request_args(&request.args) {
        Ok(args) => args,
        Err(err) => return live_admin_typed_error(err),
    };
    let message = format!(
        "pool mount for already-imported pool '{}' must be performed by the live owner; the current {} owner has no secondary mount implementation for mountpoint '{}' dataset '{}' (read_only={}, relatime={})",
        manifest.pool_name,
        manifest.owner_kind,
        mountpoint,
        dataset,
        read_only,
        relatime,
    );
    LivePoolAdminResponse::error(1, message)
}

fn pool_mount_request_args(
    args: &LivePoolAdminArgs,
) -> Result<(&str, &str, bool, bool), LivePoolAdminError> {
    validate_request_arg_names(args, &["mountpoint", "dataset", "read_only", "relatime"])?;
    Ok((
        request_arg_str(args, "mountpoint")?.unwrap_or("<unspecified>"),
        request_arg_str(args, "dataset")?.unwrap_or("root"),
        request_arg_bool(args, "read_only")?.unwrap_or(false),
        request_arg_bool(args, "relatime")?.unwrap_or(false),
    ))
}

fn pool_export(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
    #[cfg(feature = "block-volume")] block_export: &Arc<Mutex<Option<ActiveBlockExport>>>,
    shutdown: &Arc<AtomicBool>,
) -> LivePoolAdminResponse {
    if let Err(err) = validate_pool_export_request_args(&request.args) {
        return live_admin_typed_error(err);
    }

    shutdown.store(true, Ordering::Release);
    #[cfg(feature = "block-volume")]
    stop_active_block_export(block_export);
    let value = json!({
        "pool_name": manifest.pool_name,
        "pool_uuid": manifest.pool_uuid,
        "state": "ExportRequested",
        "owner_kind": manifest.owner_kind,
        "pid": manifest.pid,
        "backing_dir": manifest.backing_dir,
        "mountpoint": manifest.mountpoint,
        "operation": "export",
        "shutdown_requested": true,
    });
    if request.output.wants_json() {
        LivePoolAdminResponse::ok_machine_json(value.to_string())
    } else {
        LivePoolAdminResponse::ok_text(format!(
            "pool export requested: {}\n  owner:      {} (pid {})\n  mountpoint: {}\n  action:     live owner shutdown requested",
            manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
        ))
    }
}

fn pool_destroy_refused(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> LivePoolAdminResponse {
    let details = match pool_destroy_refusal_details(request, manifest) {
        Ok(details) => details,
        Err(err) => return live_admin_typed_error(err),
    };
    let message = pool_destroy_refusal_message(&details, manifest);
    if request.output.wants_json() {
        LivePoolAdminResponse::error_machine_json(
            1,
            message.clone(),
            pool_destroy_refusal_json(&details, manifest, &message).to_string(),
        )
    } else {
        LivePoolAdminResponse::error(1, pool_destroy_refusal_text(&details, &message))
    }
}

fn live_admin_typed_error(err: LivePoolAdminError) -> LivePoolAdminResponse {
    match serde_json::to_string(&err.kind) {
        Ok(machine_json) => {
            LivePoolAdminResponse::error_machine_json(err.exit_code, err.message, machine_json)
        }
        Err(_) => LivePoolAdminResponse::error(err.exit_code, err.message),
    }
}

fn live_admin_malformed(message: impl Into<String>) -> LivePoolAdminResponse {
    live_admin_typed_error(LivePoolAdminError::malformed(message))
}

#[derive(Debug)]
struct PoolDestroyRefusalDetails {
    force: bool,
    zero_superblock: bool,
    safe_path: String,
    shutdown_sequence: &'static str,
    label_superblock_action: &'static str,
    crash_retry: &'static str,
    claim_boundary: &'static str,
}

fn pool_destroy_refusal_details(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> Result<PoolDestroyRefusalDetails, LivePoolAdminError> {
    validate_request_arg_names(&request.args, &["force", "zero_superblock"])?;
    let force = request_arg_bool(&request.args, "force")?.unwrap_or(false);
    let zero_superblock = request_arg_bool(&request.args, "zero_superblock")?.unwrap_or(false);
    let safe_path = format!(
        "tidefsctl pool export {}; tidefsctl pool destroy {} --devices <exported-device>...{}",
        manifest.pool_name,
        manifest.pool_name,
        if zero_superblock {
            " --zero-superblock"
        } else {
            ""
        },
    );
    Ok(PoolDestroyRefusalDetails {
        force,
        zero_superblock,
        safe_path,
        shutdown_sequence: "export or unmount the pool first, wait for live-owner shutdown, then destroy exported storage with explicit --devices",
        label_superblock_action: "none",
        crash_retry: "no destructive live-owner action has started; retry after the pool is exported/offline",
        claim_boundary: "local-pool-device-lifecycle remains blocked until runtime/device evidence validates live-owner destroy behavior",
    })
}

fn pool_destroy_refusal_json(
    details: &PoolDestroyRefusalDetails,
    manifest: &LiveOwnerManifest,
    message: &str,
) -> serde_json::Value {
    json!({
        "ok": false,
        "code": "live-owner-pool-destroy-refused",
        "operation": "destroy",
        "pool_name": manifest.pool_name,
        "pool_uuid": manifest.pool_uuid,
        "state": "DestroyRefusedLiveOwnerMounted",
        "owner_kind": manifest.owner_kind,
        "pid": manifest.pid,
        "backing_dir": manifest.backing_dir,
        "mountpoint": manifest.mountpoint,
        "force_requested": details.force,
        "zero_superblock_requested": details.zero_superblock,
        "allowed_states": ["exported-offline-explicit-devices"],
        "force_semantics": "force cannot override an imported or mounted live-owner refusal; the existing offline explicit-device destroy path keeps its confirmation semantics",
        "mounted_dataset_refusal": true,
        "shutdown_requested": false,
        "shutdown_sequence": details.shutdown_sequence,
        "label_superblock_action": details.label_superblock_action,
        "safe_path": details.safe_path.as_str(),
        "crash_retry": details.crash_retry,
        "product_claim_evidence": false,
        "claim_boundary": details.claim_boundary,
        "error": message,
    })
}

fn pool_destroy_refusal_message(
    details: &PoolDestroyRefusalDetails,
    manifest: &LiveOwnerManifest,
) -> String {
    let force = details.force;
    let zero_superblock = details.zero_superblock;
    format!(
        "live-owner pool destroy refused for imported pool '{}' (owner={} pid={} mountpoint={}): mounted/imported destruction is fail-closed; force_requested={force} cannot override this boundary; zero_superblock_requested={zero_superblock} is not applied while the owner is live; export or unmount the pool, wait for owner shutdown, then destroy exported storage with explicit --devices",
        manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
    )
}

fn pool_destroy_refusal_text(details: &PoolDestroyRefusalDetails, message: &str) -> String {
    format!(
        "{}\n  allowed_state: exported/offline pool with explicit --devices\n  shutdown_sequence: {}\n  label_superblock_action: {}\n  crash_retry: {}\n  safe_path: {}\n  claim_evidence: none; {}",
        message,
        details.shutdown_sequence,
        details.label_superblock_action,
        details.crash_retry,
        details.safe_path,
        details.claim_boundary
    )
}

fn validate_request_arg_names(
    args: &LivePoolAdminArgs,
    allowed: &[&str],
) -> Result<(), LivePoolAdminError> {
    if let Some(name) = args.0.keys().find(|name| !allowed.contains(&name.as_str())) {
        return Err(LivePoolAdminError::malformed(format!(
            "live-owner request has unsupported argument '{name}'"
        )));
    }
    Ok(())
}

fn validate_pool_import_request_args(args: &LivePoolAdminArgs) -> Result<(), LivePoolAdminError> {
    validate_request_arg_names(
        args,
        &["read_only", "lock_dir", "encryption_envelope", "devices"],
    )?;
    request_arg_bool(args, "read_only")?;
    request_arg_str(args, "lock_dir")?;
    request_arg_str(args, "encryption_envelope")?;
    request_arg_string_array(args, "devices")?;
    Ok(())
}

fn validate_pool_export_request_args(args: &LivePoolAdminArgs) -> Result<(), LivePoolAdminError> {
    validate_request_arg_names(args, &["force"])?;
    request_arg_bool(args, "force")?;
    Ok(())
}

fn request_arg_bool(
    args: &LivePoolAdminArgs,
    name: &str,
) -> Result<Option<bool>, LivePoolAdminError> {
    match args.0.get(name) {
        None | Some(LivePoolAdminArg::Null) => Ok(None),
        Some(LivePoolAdminArg::Bool(value)) => Ok(Some(*value)),
        Some(_) => Err(LivePoolAdminError::malformed(format!(
            "live-owner request argument '{name}' must be a boolean"
        ))),
    }
}

fn request_arg_str<'a>(
    args: &'a LivePoolAdminArgs,
    name: &str,
) -> Result<Option<&'a str>, LivePoolAdminError> {
    match args.0.get(name) {
        None | Some(LivePoolAdminArg::Null) => Ok(None),
        Some(LivePoolAdminArg::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(LivePoolAdminError::malformed(format!(
            "live-owner request argument '{name}' must be a string"
        ))),
    }
}

#[cfg(feature = "block-volume")]
fn request_arg_u64(
    args: &LivePoolAdminArgs,
    name: &str,
) -> Result<Option<u64>, LivePoolAdminError> {
    match args.0.get(name) {
        None | Some(LivePoolAdminArg::Null) => Ok(None),
        Some(LivePoolAdminArg::U64(value)) => Ok(Some(*value)),
        Some(_) => Err(LivePoolAdminError::malformed(format!(
            "live-owner request argument '{name}' must be an unsigned integer"
        ))),
    }
}

#[cfg(feature = "block-volume")]
fn request_arg_u16(
    args: &LivePoolAdminArgs,
    name: &str,
) -> Result<Option<u16>, LivePoolAdminError> {
    request_arg_u64(args, name)?
        .map(|value| {
            u16::try_from(value).map_err(|_| {
                LivePoolAdminError::malformed(format!(
                    "live-owner request argument '{name}' exceeds u16"
                ))
            })
        })
        .transpose()
}

fn request_arg_string_array(
    args: &LivePoolAdminArgs,
    name: &str,
) -> Result<(), LivePoolAdminError> {
    match args.0.get(name) {
        None | Some(LivePoolAdminArg::Null) => Ok(()),
        Some(LivePoolAdminArg::Array(values))
            if values
                .iter()
                .all(|value| matches!(value, LivePoolAdminArg::String(_))) =>
        {
            Ok(())
        }
        Some(_) => Err(LivePoolAdminError::malformed(format!(
            "live-owner request argument '{name}' must be an array of strings"
        ))),
    }
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "block-volume")]
    use tidefs_block_volume_adapter_daemon::storage_backend::PoolRuntime;

    fn manifest() -> LiveOwnerManifest {
        LiveOwnerManifest {
            protocol: "tidefs-live-owner-admin-v1".to_string(),
            owner_kind: "fuse".to_string(),
            pool_name: "tank".to_string(),
            pool_uuid: "0123456789abcdeffedcba9876543210".to_string(),
            pid: 42,
            backing_dir: "/var/lib/tidefs/tank".to_string(),
            mountpoint: "/mnt/tank".to_string(),
            socket_path: "/run/tidefs/pools/tank/owner.sock".to_string(),
            read_only: false,
        }
    }

    #[test]
    fn request_uuid_validation_accepts_matching_uuid() {
        let manifest = manifest();

        assert!(
            validate_requested_pool_uuid(Some("0123456789ABCDEFFEDCBA9876543210"), &manifest)
                .is_ok()
        );
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn block_attach_args_require_named_volume_and_decode_geometry() {
        let args = LivePoolAdminArgs(
            [
                (
                    "volume".to_string(),
                    LivePoolAdminArg::String("vol".to_string()),
                ),
                ("nr_hw_queues".to_string(), LivePoolAdminArg::U64(2)),
                ("queue_depth".to_string(), LivePoolAdminArg::U64(128)),
                ("drain_deadline_secs".to_string(), LivePoolAdminArg::U64(45)),
            ]
            .into_iter()
            .collect(),
        );

        assert_eq!(
            block_attach_request_args(&args).expect("decode block attach arguments"),
            ("vol", 2, 128, 45)
        );
        assert!(block_attach_request_args(&LivePoolAdminArgs::default()).is_err());
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn stopping_active_block_export_sets_its_shutdown_flag() {
        let shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(Some(ActiveBlockExport {
            volume: "vol".to_string(),
            shutdown: Arc::clone(&shutdown),
        })));

        stop_active_block_export(&active);

        assert!(shutdown.load(Ordering::Acquire));
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn volume_mutation_admission_refuses_active_target() {
        let active = Arc::new(Mutex::new(Some(ActiveBlockExport {
            volume: "vol".to_string(),
            shutdown: Arc::new(AtomicBool::new(false)),
        })));
        let active = active.lock().unwrap();
        let error = ensure_volume_mutation_allowed(&active, "vol").unwrap_err();
        assert!(error.contains("actively exported"));
        assert!(error.contains("close the block export"));
        assert!(ensure_volume_mutation_allowed(&active, "other").is_ok());
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn volume_mutation_admission_stays_locked_through_delegation() {
        let active = Arc::new(Mutex::new(None));

        with_volume_mutation_admission(&active, "vol", || {
            assert!(matches!(
                active.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
        })
        .unwrap();

        assert!(active.try_lock().is_ok());
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn standalone_block_owner_routes_snapshot_to_active_export_admission() {
        use std::fs::OpenOptions;

        use tidefs_dataset_lifecycle::{DatasetFlags, DatasetId, SyncGuarantee};
        use tidefs_local_object_store::{PoolRedundancyPolicy, StoreOptions};

        let dir = tempfile::tempdir().unwrap();
        let device = dir.path().join("device.img");
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&device)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();
        let mut runtime = PoolRuntime::open_block_devices(
            &dir.path().join("metadata"),
            std::slice::from_ref(&device),
            "tank",
            PoolRedundancyPolicy::default(),
            &StoreOptions::default(),
        )
        .unwrap();
        runtime
            .create_volume(
                "vol",
                DatasetId::from_bytes([7; 16]),
                4 * 1024 * 1024,
                Vec::new(),
                DatasetFlags::NONE,
                SyncGuarantee::Local,
            )
            .unwrap();
        let runtime = Arc::new(Mutex::new(runtime));
        let shutdown = Arc::new(AtomicBool::new(false));
        let runtime_dir = dir.path().join("runtime");
        let owner = start_block_owner(
            LiveOwnerConfig {
                pool_name: "tank".to_string(),
                pool_uuid: [9; 16],
                backing_dir: dir.path().join("metadata"),
                mountpoint: PathBuf::from("ublk:vol"),
                runtime_dir: runtime_dir.clone(),
                read_only: false,
            },
            Arc::clone(&runtime),
            "vol".to_string(),
            Arc::clone(&shutdown),
        )
        .unwrap();

        let manifest: LiveOwnerManifest =
            serde_json::from_slice(&fs::read(runtime_dir.join("owner.json")).unwrap()).unwrap();
        assert_eq!(manifest.owner_kind, "ublk");

        for (command, args) in [
            (
                LivePoolAdminCommand::DatasetResize,
                [
                    ("name".to_string(), LivePoolAdminArg::String("vol".into())),
                    ("size".to_string(), LivePoolAdminArg::U64(8 * 1024 * 1024)),
                ]
                .into_iter()
                .collect(),
            ),
            (
                LivePoolAdminCommand::DatasetRename,
                [
                    (
                        "old_name".to_string(),
                        LivePoolAdminArg::String("vol".into()),
                    ),
                    (
                        "new_name".to_string(),
                        LivePoolAdminArg::String("renamed".into()),
                    ),
                ]
                .into_iter()
                .collect(),
            ),
            (
                LivePoolAdminCommand::DatasetDestroy,
                [("name".to_string(), LivePoolAdminArg::String("vol".into()))]
                    .into_iter()
                    .collect(),
            ),
            (
                LivePoolAdminCommand::SnapshotCreate,
                [(
                    "target".to_string(),
                    LivePoolAdminArg::String("vol@before".into()),
                )]
                .into_iter()
                .collect(),
            ),
            (
                LivePoolAdminCommand::SnapshotRollback,
                [(
                    "target".to_string(),
                    LivePoolAdminArg::String("vol@before".into()),
                )]
                .into_iter()
                .collect(),
            ),
            (
                LivePoolAdminCommand::SnapshotDestroy,
                [(
                    "target".to_string(),
                    LivePoolAdminArg::String("vol@before".into()),
                )]
                .into_iter()
                .collect(),
            ),
        ] {
            let mut stream = UnixStream::connect(runtime_dir.join("owner.sock")).unwrap();
            let mut request = LivePoolAdminRequest::new(command, "tank");
            request.args = LivePoolAdminArgs(args);
            writeln!(stream, "{}", serde_json::to_string(&request).unwrap()).unwrap();
            let mut response = String::new();
            BufReader::new(stream).read_line(&mut response).unwrap();
            let response: LivePoolAdminResponse = serde_json::from_str(&response).unwrap();
            assert_eq!(response.exit_code, 1);
            let LivePoolAdminResponseBody::Error { message, .. } = response.body else {
                panic!("active export should refuse the mutation");
            };
            assert!(message.contains("actively exported"), "{message}");
        }
        assert!(runtime
            .lock()
            .unwrap()
            .list_volume_snapshots()
            .unwrap()
            .is_empty());

        owner.stop();
        assert!(!runtime_dir.join("owner.json").exists());
        assert!(!runtime_dir.join("owner.sock").exists());
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn volume_snapshot_mutation_targets_source_and_filesystem_requests_delegate() {
        for command in [
            LivePoolAdminCommand::SnapshotCreate,
            LivePoolAdminCommand::SnapshotDestroy,
            LivePoolAdminCommand::SnapshotRollback,
        ] {
            let mut request = LivePoolAdminRequest::new(command, "tank");
            request.args = LivePoolAdminArgs(
                [(
                    "target".to_string(),
                    LivePoolAdminArg::String("vol@before".to_string()),
                )]
                .into_iter()
                .collect(),
            );
            assert_eq!(volume_mutation_target(&request).unwrap(), Some("vol"));

            request.args = LivePoolAdminArgs(
                [(
                    "target".to_string(),
                    LivePoolAdminArg::String("vol@snap@nested".to_string()),
                )]
                .into_iter()
                .collect(),
            );
            assert!(volume_mutation_target(&request).is_err());

            request.args = LivePoolAdminArgs(
                [(
                    "name".to_string(),
                    LivePoolAdminArg::String("before".to_string()),
                )]
                .into_iter()
                .collect(),
            );
            assert_eq!(volume_mutation_target(&request).unwrap(), None);
        }
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn block_export_reservation_refuses_owner_shutdown() {
        let owner_shutdown = Arc::new(AtomicBool::new(true));
        let export_shutdown = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(None));

        let error = reserve_block_export(&active, &owner_shutdown, "tank", "vol", &export_shutdown)
            .unwrap_err();

        assert_eq!(error, "live owner is shutting down");
        assert!(active.lock().unwrap().is_none());
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn client_disconnect_stops_block_export() {
        let (server, client) = UnixStream::pair().expect("create client socket pair");
        let stop = Arc::new(AtomicBool::new(false));
        let export_shutdown = Arc::new(AtomicBool::new(false));
        let monitor = monitor_client_disconnect(server, stop, Arc::clone(&export_shutdown));

        drop(client);
        monitor.join().expect("join disconnect monitor");

        assert!(export_shutdown.load(Ordering::Acquire));
    }

    #[test]
    fn request_uuid_validation_accepts_name_only_requests() {
        let manifest = manifest();

        assert!(validate_requested_pool_uuid(None, &manifest).is_ok());
    }

    #[test]
    fn request_uuid_validation_rejects_mismatched_uuid() {
        let manifest = manifest();

        let err = validate_requested_pool_uuid(Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), &manifest)
            .unwrap_err();

        assert!(err.contains("owns uuid 0123456789abcdeffedcba9876543210"));
        assert!(err.contains("not requested uuid aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    fn assert_typed_malformed(response: LivePoolAdminResponse) -> String {
        assert_eq!(response.exit_code, 2);
        let LivePoolAdminResponseBody::Error {
            message,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("malformed request should carry typed machine JSON");
        };

        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("malformed")
        );
        message
    }

    #[test]
    fn pool_name_mismatch_uses_typed_malformed_error() {
        let manifest = manifest();
        let mut request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolStatus, "other");
        request.pool_uuid = Some("0123456789abcdeffedcba9876543210".to_string());

        let response = validate_request_pool_identity(&request, &manifest).unwrap_err();
        let message = assert_typed_malformed(response);

        assert!(message.contains("cannot serve pool 'other'"));
    }

    #[test]
    fn pool_uuid_mismatch_uses_typed_malformed_error() {
        let manifest = manifest();
        let mut request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolStatus, "tank");
        request.pool_uuid = Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string());

        let response = validate_request_pool_identity(&request, &manifest).unwrap_err();
        let message = assert_typed_malformed(response);

        assert!(message.contains("owns uuid 0123456789abcdeffedcba9876543210"));
        assert!(message.contains("not requested uuid aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    #[test]
    fn typed_request_payload_preserves_pool_uuid() {
        let request = LivePoolAdminRequest {
            version: LIVE_POOL_ADMIN_PROTOCOL_VERSION,
            command: LivePoolAdminCommand::DatasetList,
            pool: "tank".to_string(),
            pool_uuid: Some("0123456789abcdeffedcba9876543210".to_string()),
            output: LivePoolAdminOutput::MachineJson,
            args: LivePoolAdminArgs::default(),
        };

        let payload: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&request).unwrap()).unwrap();

        assert_eq!(
            payload.get("pool_uuid").and_then(serde_json::Value::as_str),
            Some("0123456789abcdeffedcba9876543210")
        );
    }

    #[test]
    fn delegated_unsupported_admin_request_uses_typed_command_error() {
        let request = LivePoolAdminRequest::new(LivePoolAdminCommand::DatasetList, "tank");

        let response = unsupported_admin_command_response(&request);

        assert_eq!(response.exit_code, 1);
        let LivePoolAdminResponseBody::Error {
            message,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("unsupported admin request should carry typed machine JSON");
        };
        assert_eq!(
            message,
            "unsupported live-owner command tidefsctl dataset list"
        );
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("unsupported_command")
        );
        assert_eq!(
            value.get("command").and_then(serde_json::Value::as_str),
            Some("dataset")
        );
        assert_eq!(
            value.get("operation").and_then(serde_json::Value::as_str),
            Some("list")
        );
    }

    #[test]
    fn unknown_wire_command_decodes_as_typed_unsupported_command() {
        let err = decode_live_pool_admin_request(
            r#"{"version":1,"command":"cluster_promote","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
        )
        .unwrap_err();

        assert_eq!(err.exit_code, 1);
        let response = live_admin_typed_error(err);
        let LivePoolAdminResponseBody::Error {
            message,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("unsupported command should carry typed machine JSON");
        };
        assert_eq!(
            message,
            "unsupported live-owner command tidefsctl cluster promote"
        );
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("unsupported_command")
        );
        assert_eq!(
            value.get("command").and_then(serde_json::Value::as_str),
            Some("cluster")
        );
        assert_eq!(
            value.get("operation").and_then(serde_json::Value::as_str),
            Some("promote")
        );
    }

    #[test]
    fn device_status_wire_command_decodes_to_typed_route() {
        let request = decode_live_pool_admin_request(
            r#"{"version":1,"command":"device_status","pool":"tank","pool_uuid":null,"output":"machine_json","args":{}}"#,
        )
        .unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::DeviceStatus);
        assert_eq!(request.output, LivePoolAdminOutput::MachineJson);
        assert_eq!(request.pool, "tank");
    }

    #[test]
    fn device_status_without_engine_source_returns_typed_refusal() {
        let request = LivePoolAdminRequest::new(LivePoolAdminCommand::DeviceStatus, "tank");

        let response = unsupported_admin_command_response(&request);

        assert_eq!(response.exit_code, 1);
        let LivePoolAdminResponseBody::Error {
            message,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("device status refusal should carry typed machine detail");
        };
        assert_eq!(
            message,
            "unsupported live-owner command tidefsctl device status"
        );
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(value["kind"], "unsupported_command");
        assert_eq!(value["command"], "device");
        assert_eq!(value["operation"], "status");
    }

    #[test]
    fn unknown_request_envelope_field_decodes_as_typed_malformed() {
        let err = decode_live_pool_admin_request(
            r#"{"version":1,"command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{},"unexpected":true}"#,
        )
        .unwrap_err();

        assert_eq!(err.exit_code, 2);
        assert_eq!(err.kind, LivePoolAdminErrorKind::Malformed);
        assert!(err.message.contains("unknown field `unexpected`"));
    }

    #[test]
    fn malformed_wire_version_decodes_as_typed_malformed() {
        for (payload, detail) in [
            (
                r#"{"command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
                "missing version",
            ),
            (
                r#"{"version":"1","command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
                "malformed version",
            ),
            (
                r#"{"version":-1,"command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
                "malformed version",
            ),
            (
                r#"{"version":1.0,"command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
                "malformed version",
            ),
            (
                r#"{"version":65536,"command":"pool_status","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
                "malformed version",
            ),
        ] {
            let err = decode_live_pool_admin_request(payload).unwrap_err();

            assert_eq!(err.exit_code, 2);
            assert_eq!(err.kind, LivePoolAdminErrorKind::Malformed);
            let response = live_admin_typed_error(err);
            let LivePoolAdminResponseBody::Error {
                message,
                machine_json: Some(machine_json),
            } = response.body
            else {
                panic!("malformed version should carry typed machine JSON");
            };
            assert!(message.contains(detail));
            let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
            assert_eq!(
                value.get("kind").and_then(serde_json::Value::as_str),
                Some("malformed")
            );
        }
    }

    #[test]
    fn unsupported_version_takes_precedence_over_unknown_wire_command() {
        let err = decode_live_pool_admin_request(
            r#"{"version":42,"command":"cluster_promote","pool":"tank","pool_uuid":null,"output":"human","args":{}}"#,
        )
        .unwrap_err();

        assert_eq!(err.exit_code, 2);
        assert_eq!(
            err.kind,
            LivePoolAdminErrorKind::UnsupportedVersion { version: 42 }
        );
        let response = live_admin_typed_error(err);
        let LivePoolAdminResponseBody::Error {
            message: _,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("unsupported version should carry typed machine JSON");
        };
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("unsupported_version")
        );
        assert_eq!(
            value.get("version").and_then(serde_json::Value::as_u64),
            Some(42)
        );
    }

    #[test]
    fn pool_mount_request_fails_until_owner_can_mount() {
        let manifest = manifest();
        let request = LivePoolAdminRequest {
            version: LIVE_POOL_ADMIN_PROTOCOL_VERSION,
            command: LivePoolAdminCommand::PoolMount,
            pool: "tank".to_string(),
            pool_uuid: None,
            output: LivePoolAdminOutput::Human,
            args: LivePoolAdminArgs(
                [
                    (
                        "mountpoint".to_string(),
                        LivePoolAdminArg::String("/mnt/other".to_string()),
                    ),
                    (
                        "dataset".to_string(),
                        LivePoolAdminArg::String("root".to_string()),
                    ),
                    ("read_only".to_string(), LivePoolAdminArg::Bool(true)),
                    ("relatime".to_string(), LivePoolAdminArg::Bool(false)),
                ]
                .into_iter()
                .collect(),
            ),
        };

        let response = pool_mount_refused(&request, &manifest);

        assert_eq!(response.exit_code, 1);
        let LivePoolAdminResponseBody::Error { message: error, .. } = response.body else {
            panic!("mount refusal should explain why");
        };
        assert!(error.contains("already-imported pool 'tank'"));
        assert!(error.contains("live owner"));
        assert!(error.contains("/mnt/other"));
        assert!(error.contains("no secondary mount implementation"));
    }

    #[test]
    fn pool_mount_malformed_arg_type_fails_closed() {
        let manifest = manifest();
        let mut request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolMount, "tank");
        request.args.0.insert(
            "read_only".to_string(),
            LivePoolAdminArg::String("yes".to_string()),
        );

        let message = assert_typed_malformed(pool_mount_refused(&request, &manifest));

        assert!(message.contains("argument 'read_only' must be a boolean"));
    }

    #[test]
    fn pool_import_malformed_args_fail_closed() {
        let manifest = manifest();
        let mut request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolImport, "tank");
        request.args.0.insert(
            "devices".to_string(),
            LivePoolAdminArg::Array(vec![LivePoolAdminArg::Bool(true)]),
        );

        let message = assert_typed_malformed(already_owned(&request, "import", &manifest));

        assert!(message.contains("argument 'devices' must be an array of strings"));
    }

    #[test]
    fn pool_export_malformed_args_fail_before_shutdown() {
        let manifest = manifest();
        let shutdown = Arc::new(AtomicBool::new(false));
        #[cfg(feature = "block-volume")]
        let block_export = Arc::new(Mutex::new(None));
        let mut valid = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolExport, "tank");
        valid
            .args
            .0
            .insert("force".to_string(), LivePoolAdminArg::Bool(true));

        let response = pool_export(
            &valid,
            &manifest,
            #[cfg(feature = "block-volume")]
            &block_export,
            &shutdown,
        );

        assert_eq!(response.exit_code, 0);
        assert!(shutdown.load(Ordering::Acquire));

        for (name, value, detail) in [
            (
                "force",
                LivePoolAdminArg::String("yes".to_string()),
                "argument 'force' must be a boolean",
            ),
            (
                "unexpected",
                LivePoolAdminArg::Bool(true),
                "unsupported argument 'unexpected'",
            ),
        ] {
            let shutdown = Arc::new(AtomicBool::new(false));
            #[cfg(feature = "block-volume")]
            let block_export = Arc::new(Mutex::new(None));
            let mut request = LivePoolAdminRequest::new(LivePoolAdminCommand::PoolExport, "tank");
            request.args.0.insert(name.to_string(), value);

            let message = assert_typed_malformed(pool_export(
                &request,
                &manifest,
                #[cfg(feature = "block-volume")]
                &block_export,
                &shutdown,
            ));

            assert!(message.contains(detail));
            assert!(!shutdown.load(Ordering::Acquire));
        }
    }

    fn destroy_request(wants_json: bool) -> LivePoolAdminRequest {
        LivePoolAdminRequest {
            version: LIVE_POOL_ADMIN_PROTOCOL_VERSION,
            command: LivePoolAdminCommand::PoolDestroy,
            pool: "tank".to_string(),
            pool_uuid: Some("0123456789abcdeffedcba9876543210".to_string()),
            output: if wants_json {
                LivePoolAdminOutput::MachineJson
            } else {
                LivePoolAdminOutput::Human
            },
            args: LivePoolAdminArgs(
                [
                    ("force".to_string(), LivePoolAdminArg::Bool(true)),
                    ("zero_superblock".to_string(), LivePoolAdminArg::Bool(true)),
                ]
                .into_iter()
                .collect(),
            ),
        }
    }

    #[test]
    fn pool_destroy_json_refusal_names_safe_offline_boundary() {
        let manifest = manifest();
        let request = destroy_request(true);

        let response = pool_destroy_refused(&request, &manifest);

        assert_eq!(response.exit_code, 1);
        let LivePoolAdminResponseBody::Error {
            message: _,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("destroy refusal should carry machine JSON");
        };
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("code").and_then(serde_json::Value::as_str),
            Some("live-owner-pool-destroy-refused")
        );
        assert_eq!(
            value
                .get("force_requested")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            value
                .get("zero_superblock_requested")
                .and_then(serde_json::Value::as_bool),
            Some(true)
        );
        assert_eq!(
            value
                .get("shutdown_requested")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        assert_eq!(
            value
                .get("label_superblock_action")
                .and_then(serde_json::Value::as_str),
            Some("none")
        );
        assert_eq!(
            value
                .get("product_claim_evidence")
                .and_then(serde_json::Value::as_bool),
            Some(false)
        );
        let safe_path = value
            .get("safe_path")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        assert!(safe_path.contains("pool export tank"));
        assert!(safe_path.contains("--devices <exported-device>"));
        assert!(safe_path.contains("--zero-superblock"));
        let error = value
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap();
        assert!(error.contains("fail-closed"));
        assert!(!error.contains("not implemented"));
    }

    #[test]
    fn pool_destroy_unknown_arg_fails_closed() {
        let manifest = manifest();
        let mut request = destroy_request(false);
        request
            .args
            .0
            .insert("unexpected".to_string(), LivePoolAdminArg::Bool(true));

        let message = assert_typed_malformed(pool_destroy_refused(&request, &manifest));

        assert!(message.contains("unsupported argument 'unexpected'"));
    }

    #[test]
    fn typed_error_response_preserves_error_kind_machine_json() {
        let response = live_admin_typed_error(LivePoolAdminError::unsupported_version(42));

        assert_eq!(response.exit_code, 2);
        let LivePoolAdminResponseBody::Error {
            message: _,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("typed error should carry machine JSON");
        };

        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("unsupported_version")
        );
        assert_eq!(
            value.get("version").and_then(serde_json::Value::as_u64),
            Some(42)
        );
    }

    #[test]
    fn empty_live_owner_request_uses_typed_malformed_error() {
        let response = live_admin_malformed("empty live-owner request");

        assert_eq!(response.exit_code, 2);
        let LivePoolAdminResponseBody::Error {
            message,
            machine_json: Some(machine_json),
        } = response.body
        else {
            panic!("empty request should carry typed malformed machine JSON");
        };

        assert_eq!(message, "empty live-owner request");
        let value: serde_json::Value = serde_json::from_str(&machine_json).unwrap();
        assert_eq!(
            value.get("kind").and_then(serde_json::Value::as_str),
            Some("malformed")
        );
    }

    #[test]
    fn pool_destroy_text_refusal_records_state_machine() {
        let manifest = manifest();
        let request = destroy_request(false);

        let response = pool_destroy_refused(&request, &manifest);

        assert_eq!(response.exit_code, 1);
        let LivePoolAdminResponseBody::Error {
            message: error,
            machine_json,
        } = response.body
        else {
            panic!("destroy refusal should explain why");
        };
        assert!(machine_json.is_none());
        assert!(error.contains("allowed_state: exported/offline pool"));
        assert!(error.contains("shutdown_sequence"));
        assert!(error.contains("label_superblock_action: none"));
        assert!(error.contains("crash_retry"));
        assert!(error.contains("pool destroy tank --devices"));
        assert!(error.contains("local-pool-device-lifecycle remains blocked"));
        assert!(!error.contains("not implemented"));
    }
}
