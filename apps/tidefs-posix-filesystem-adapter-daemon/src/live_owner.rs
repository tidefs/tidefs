// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Userspace live-pool owner endpoint.
//!
//! This is the FUSE-session side of the imported-pool authority boundary:
//! pool-name commands talk to the runtime that owns cached state instead of
//! reopening devices or metadata directories behind it.
//! When a client knows the pool UUID, the request carries it and this owner
//! must prove the UUID matches before serving live cached state.

use std::fs;
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
use tidefs_types_vfs_core::RequestCtx;
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminError,
    LivePoolAdminRequest, LivePoolAdminResponse, VfsEngineStatFs, LIVE_POOL_ADMIN_PROTOCOL_VERSION,
};
#[cfg(test)]
use tidefs_vfs_engine::{LivePoolAdminOutput, LivePoolAdminResponseBody};

pub type LiveOwnerEngine = Arc<Mutex<Box<dyn VfsEngineStatFs + Send>>>;

#[derive(Clone, Debug)]
pub struct LiveOwnerConfig {
    pub pool_name: String,
    pub pool_uuid: [u8; 16],
    pub backing_dir: PathBuf,
    pub mountpoint: PathBuf,
    pub runtime_dir: PathBuf,
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
}

pub struct LiveOwnerHandle {
    shutdown: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    socket_path: PathBuf,
    manifest_path: PathBuf,
}

impl LiveOwnerHandle {
    pub fn stop(mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        cleanup_endpoint(&self.socket_path, &self.manifest_path);
    }
}

impl Drop for LiveOwnerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
        cleanup_endpoint(&self.socket_path, &self.manifest_path);
    }
}

pub fn start_fuse_owner(
    config: LiveOwnerConfig,
    engine: LiveOwnerEngine,
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
        owner_kind: "fuse".to_string(),
        pool_name: config.pool_name.clone(),
        pool_uuid: hex_uuid(&config.pool_uuid),
        pid: std::process::id(),
        backing_dir: fs::canonicalize(&config.backing_dir)
            .unwrap_or_else(|_| config.backing_dir.clone())
            .display()
            .to_string(),
        mountpoint: config.mountpoint.display().to_string(),
        socket_path: socket_path.display().to_string(),
    };
    write_manifest(&manifest_path, &manifest)?;

    let thread_manifest = manifest.clone();
    let thread_shutdown = Arc::clone(&shutdown);
    let join = thread::spawn(move || {
        while !thread_shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    handle_client(stream, &thread_manifest, &engine, &thread_shutdown);
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
    });

    Ok(LiveOwnerHandle {
        shutdown,
        join: Some(join),
        socket_path,
        manifest_path,
    })
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
    engine: &LiveOwnerEngine,
    shutdown: &Arc<AtomicBool>,
) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let response = match reader.read_line(&mut line) {
        Ok(0) => LivePoolAdminResponse::error(2, "empty live-owner request"),
        Ok(_) => match serde_json::from_str::<LivePoolAdminRequest>(&line) {
            Ok(request) => dispatch_request(request, manifest, engine, shutdown),
            Err(err) => live_admin_typed_error(LivePoolAdminError::malformed(format!(
                "decode live-owner request: {err}"
            ))),
        },
        Err(err) => LivePoolAdminResponse::error(2, format!("read live-owner request: {err}")),
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

fn dispatch_request(
    request: LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
    engine: &LiveOwnerEngine,
    shutdown: &Arc<AtomicBool>,
) -> LivePoolAdminResponse {
    if let Err(err) = request.validate_version() {
        return live_admin_typed_error(err);
    }
    if request.pool != manifest.pool_name {
        return LivePoolAdminResponse::error(
            2,
            format!(
                "live owner for pool '{}' cannot serve pool '{}'",
                manifest.pool_name, request.pool
            ),
        );
    }
    if let Err(message) = validate_requested_pool_uuid(request.pool_uuid.as_deref(), manifest) {
        return LivePoolAdminResponse::error(2, message);
    }

    match request.command {
        LivePoolAdminCommand::PoolStatus => {
            pool_status(request.output.wants_json(), manifest, engine)
        }
        LivePoolAdminCommand::PoolImport => {
            already_owned("import", manifest, request.output.wants_json())
        }
        LivePoolAdminCommand::PoolMount => pool_mount_refused(&request, manifest),
        LivePoolAdminCommand::PoolExport => {
            pool_export(request.output.wants_json(), manifest, shutdown)
        }
        LivePoolAdminCommand::PoolDestroy => pool_destroy_refused(&request, manifest),
        LivePoolAdminCommand::PoolGet
        | LivePoolAdminCommand::PoolSet
        | LivePoolAdminCommand::PoolListProps
        | LivePoolAdminCommand::PoolIntegrityCheck
        | LivePoolAdminCommand::DatasetCreate
        | LivePoolAdminCommand::DatasetList
        | LivePoolAdminCommand::DatasetRename
        | LivePoolAdminCommand::DatasetDestroy
        | LivePoolAdminCommand::DatasetSetStrategy
        | LivePoolAdminCommand::DatasetUpgrade
        | LivePoolAdminCommand::DatasetGet
        | LivePoolAdminCommand::DatasetSet
        | LivePoolAdminCommand::DatasetListProps
        | LivePoolAdminCommand::DatasetSealKey
        | LivePoolAdminCommand::DatasetRotateKey
        | LivePoolAdminCommand::SnapshotCreate
        | LivePoolAdminCommand::SnapshotList
        | LivePoolAdminCommand::SnapshotDestroy
        | LivePoolAdminCommand::SnapshotRollback
        | LivePoolAdminCommand::SnapshotExtract
        | LivePoolAdminCommand::SnapshotSend
        | LivePoolAdminCommand::PerformanceAdmissionSnapshot
        | LivePoolAdminCommand::DeviceRemove => delegate_admin_request(&request, engine),
    }
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
    engine: &LiveOwnerEngine,
) -> LivePoolAdminResponse {
    match engine.lock() {
        Ok(engine) => match engine.live_pool_admin_request(request) {
            Ok(response) => response,
            Err(errno) => LivePoolAdminResponse::error(
                1,
                format!("live engine does not support this admin request: {errno:?}"),
            ),
        },
        Err(_) => LivePoolAdminResponse::error(1, "live owner engine lock poisoned"),
    }
}

fn pool_status(
    wants_json: bool,
    manifest: &LiveOwnerManifest,
    engine: &LiveOwnerEngine,
) -> LivePoolAdminResponse {
    let ctx = RequestCtx {
        uid: 0,
        gid: 0,
        pid: 0,
        umask: 0,
        groups: vec![0],
    };
    let statfs = match engine.lock() {
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

    if wants_json {
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
    operation: &str,
    manifest: &LiveOwnerManifest,
    wants_json: bool,
) -> LivePoolAdminResponse {
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
    if wants_json {
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
    let mountpoint = request_arg_str(&request.args, "mountpoint").unwrap_or("<unspecified>");
    let dataset = request_arg_str(&request.args, "dataset").unwrap_or("root");
    let read_only = request_arg_bool(&request.args, "read_only").unwrap_or(false);
    let relatime = request_arg_bool(&request.args, "relatime").unwrap_or(false);
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

fn pool_export(
    wants_json: bool,
    manifest: &LiveOwnerManifest,
    shutdown: &Arc<AtomicBool>,
) -> LivePoolAdminResponse {
    shutdown.store(true, Ordering::Release);
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
    if wants_json {
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
    let message = pool_destroy_refusal_message(request, manifest);
    if request.output.wants_json() {
        LivePoolAdminResponse::error_machine_json(
            1,
            message,
            pool_destroy_refusal_json(request, manifest).to_string(),
        )
    } else {
        LivePoolAdminResponse::error(1, pool_destroy_refusal_text(request, manifest))
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

fn pool_destroy_refusal_json(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> serde_json::Value {
    let force = request_arg_bool(&request.args, "force").unwrap_or(false);
    let zero_superblock = request_arg_bool(&request.args, "zero_superblock").unwrap_or(false);
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
        "force_requested": force,
        "zero_superblock_requested": zero_superblock,
        "allowed_states": ["exported-offline-explicit-devices"],
        "force_semantics": "force cannot override an imported or mounted live-owner refusal; the existing offline explicit-device destroy path keeps its confirmation semantics",
        "mounted_dataset_refusal": true,
        "shutdown_requested": false,
        "shutdown_sequence": "export or unmount the pool first, wait for live-owner shutdown, then destroy exported storage with explicit --devices",
        "label_superblock_action": "none",
        "safe_path": safe_path,
        "crash_retry": "no destructive live-owner action has started; retry after the pool is exported/offline",
        "product_claim_evidence": false,
        "claim_boundary": "local-pool-device-lifecycle remains blocked until runtime/device evidence validates live-owner destroy behavior",
        "error": pool_destroy_refusal_message(request, manifest),
    })
}

fn pool_destroy_refusal_message(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> String {
    let force = request_arg_bool(&request.args, "force").unwrap_or(false);
    let zero_superblock = request_arg_bool(&request.args, "zero_superblock").unwrap_or(false);
    format!(
        "live-owner pool destroy refused for imported pool '{}' (owner={} pid={} mountpoint={}): mounted/imported destruction is fail-closed; force_requested={force} cannot override this boundary; zero_superblock_requested={zero_superblock} is not applied while the owner is live; export or unmount the pool, wait for owner shutdown, then destroy exported storage with explicit --devices",
        manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
    )
}

fn pool_destroy_refusal_text(
    request: &LivePoolAdminRequest,
    manifest: &LiveOwnerManifest,
) -> String {
    let value = pool_destroy_refusal_json(request, manifest);
    format!(
        "{}\n  allowed_state: exported/offline pool with explicit --devices\n  shutdown_sequence: {}\n  label_superblock_action: {}\n  crash_retry: {}\n  safe_path: {}\n  claim_evidence: none; {}",
        pool_destroy_refusal_message(request, manifest),
        value
            .get("shutdown_sequence")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("export/offline before destroy"),
        value
            .get("label_superblock_action")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("none"),
        value
            .get("crash_retry")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("no live destroy started"),
        value
            .get("safe_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("tidefsctl pool destroy <pool> --devices <exported-device>..."),
        value
            .get("claim_boundary")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("local-pool-device-lifecycle remains blocked")
    )
}

fn request_arg_bool(args: &LivePoolAdminArgs, name: &str) -> Option<bool> {
    match args.0.get(name) {
        Some(LivePoolAdminArg::Bool(value)) => Some(*value),
        _ => None,
    }
}

fn request_arg_str<'a>(args: &'a LivePoolAdminArgs, name: &str) -> Option<&'a str> {
    match args.0.get(name) {
        Some(LivePoolAdminArg::String(value)) => Some(value.as_str()),
        _ => None,
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
