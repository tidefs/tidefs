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
use tidefs_vfs_engine::VfsEngineStatFs;

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
        protocol: "tidefs-live-owner-json-v1".to_string(),
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

#[derive(Debug, Deserialize)]
struct LiveOwnerRequest {
    command: String,
    operation: String,
    pool: String,
    #[serde(default)]
    pool_uuid: Option<String>,
    json: bool,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
struct LiveOwnerResponse {
    ok: bool,
    exit_code: i32,
    text: Option<String>,
    json: Option<serde_json::Value>,
    error: Option<String>,
}

impl LiveOwnerResponse {
    fn ok_text(text: String) -> Self {
        Self {
            ok: true,
            exit_code: 0,
            text: Some(text),
            json: None,
            error: None,
        }
    }

    fn ok_json(value: serde_json::Value) -> Self {
        Self {
            ok: true,
            exit_code: 0,
            text: None,
            json: Some(value),
            error: None,
        }
    }

    fn error(exit_code: i32, message: impl Into<String>) -> Self {
        Self {
            ok: false,
            exit_code,
            text: None,
            json: None,
            error: Some(message.into()),
        }
    }
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
        Ok(0) => LiveOwnerResponse::error(2, "empty live-owner request"),
        Ok(_) => match serde_json::from_str::<LiveOwnerRequest>(&line) {
            Ok(request) => dispatch_request(request, manifest, engine, shutdown),
            Err(err) => LiveOwnerResponse::error(2, format!("decode live-owner request: {err}")),
        },
        Err(err) => LiveOwnerResponse::error(2, format!("read live-owner request: {err}")),
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
                "{{\"ok\":false,\"exit_code\":2,\"error\":\"encode response: {err}\"}}"
            );
        }
    }
}

fn dispatch_request(
    request: LiveOwnerRequest,
    manifest: &LiveOwnerManifest,
    engine: &LiveOwnerEngine,
    shutdown: &Arc<AtomicBool>,
) -> LiveOwnerResponse {
    if request.pool != manifest.pool_name {
        return LiveOwnerResponse::error(
            2,
            format!(
                "live owner for pool '{}' cannot serve pool '{}'",
                manifest.pool_name, request.pool
            ),
        );
    }
    if let Err(message) = validate_requested_pool_uuid(request.pool_uuid.as_deref(), manifest) {
        return LiveOwnerResponse::error(2, message);
    }

    match (request.command.as_str(), request.operation.as_str()) {
        ("pool", "status") => pool_status(request.json, manifest, engine),
        ("pool", "import") => already_owned("import", manifest, request.json),
        ("pool", "mount") => pool_mount_refused(&request, manifest),
        ("pool", "export") => pool_export(request.json, manifest, shutdown),
        ("pool", "destroy") => pool_destroy_refused(request.json, manifest),
        ("pool", "get" | "set" | "list-props" | "integrity-check")
        | (
            "dataset",
            "create" | "list" | "rename" | "destroy" | "set-strategy" | "upgrade" | "get" | "set"
            | "list-props" | "seal-key" | "rotate-key",
        )
        | ("snapshot", "create" | "list" | "destroy" | "rollback" | "send")
        | ("device", "remove") => delegate_admin_request(&request, engine),
        _ => LiveOwnerResponse::error(
            1,
            format!(
                "live owner '{}' does not yet implement tidefsctl {} {}",
                manifest.owner_kind, request.command, request.operation
            ),
        ),
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
    request: &LiveOwnerRequest,
    engine: &LiveOwnerEngine,
) -> LiveOwnerResponse {
    let bytes = match delegate_admin_payload(request) {
        Ok(bytes) => bytes,
        Err(err) => return LiveOwnerResponse::error(2, err),
    };
    let response_bytes = match engine.lock() {
        Ok(engine) => match engine.live_pool_admin_request(&bytes) {
            Ok(bytes) => bytes,
            Err(errno) => {
                return LiveOwnerResponse::error(
                    1,
                    format!("live engine does not support this admin request: {errno:?}"),
                )
            }
        },
        Err(_) => return LiveOwnerResponse::error(1, "live owner engine lock poisoned"),
    };
    serde_json::from_slice::<LiveOwnerResponse>(&response_bytes).unwrap_or_else(|err| {
        LiveOwnerResponse::error(2, format!("decode live admin response: {err}"))
    })
}

fn delegate_admin_payload(request: &LiveOwnerRequest) -> Result<Vec<u8>, String> {
    let mut payload = json!({
        "command": request.command.as_str(),
        "operation": request.operation.as_str(),
        "pool": request.pool.as_str(),
        "json": request.json,
        "args": &request.args,
    });
    if let Some(pool_uuid) = request.pool_uuid.as_deref() {
        payload["pool_uuid"] = serde_json::Value::String(pool_uuid.to_string());
    }
    serde_json::to_vec(&payload).map_err(|err| format!("encode live admin request: {err}"))
}

fn pool_status(
    wants_json: bool,
    manifest: &LiveOwnerManifest,
    engine: &LiveOwnerEngine,
) -> LiveOwnerResponse {
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
                return LiveOwnerResponse::error(
                    1,
                    format!("live owner statfs failed with {errno:?}"),
                )
            }
        },
        Err(_) => return LiveOwnerResponse::error(1, "live owner engine lock poisoned"),
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
        LiveOwnerResponse::ok_json(value)
    } else {
        LiveOwnerResponse::ok_text(format!(
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
) -> LiveOwnerResponse {
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
        LiveOwnerResponse::ok_json(value)
    } else {
        LiveOwnerResponse::ok_text(format!(
            "pool already imported: {}\n  owner:      {} (pid {})\n  mountpoint: {}",
            manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
        ))
    }
}

fn pool_mount_refused(
    request: &LiveOwnerRequest,
    manifest: &LiveOwnerManifest,
) -> LiveOwnerResponse {
    let mountpoint = request
        .args
        .get("mountpoint")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<unspecified>");
    let dataset = request
        .args
        .get("dataset")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("root");
    let read_only = request
        .args
        .get("read_only")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let relatime = request
        .args
        .get("relatime")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let message = format!(
        "pool mount for already-imported pool '{}' must be performed by the live owner; the current {} owner has no secondary mount implementation for mountpoint '{}' dataset '{}' (read_only={}, relatime={})",
        manifest.pool_name,
        manifest.owner_kind,
        mountpoint,
        dataset,
        read_only,
        relatime,
    );
    LiveOwnerResponse::error(1, message)
}

fn pool_export(
    wants_json: bool,
    manifest: &LiveOwnerManifest,
    shutdown: &Arc<AtomicBool>,
) -> LiveOwnerResponse {
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
        LiveOwnerResponse::ok_json(value)
    } else {
        LiveOwnerResponse::ok_text(format!(
            "pool export requested: {}\n  owner:      {} (pid {})\n  mountpoint: {}\n  action:     live owner shutdown requested",
            manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
        ))
    }
}

fn pool_destroy_refused(wants_json: bool, manifest: &LiveOwnerManifest) -> LiveOwnerResponse {
    let message = "pool destroy is not implemented for the live userspace owner; export or unmount the pool, then destroy exported storage with --devices";
    if wants_json {
        LiveOwnerResponse::error(1, message)
    } else {
        LiveOwnerResponse::error(
            1,
            format!(
                "{message} (pool '{}' owner={} pid={} mountpoint={})",
                manifest.pool_name, manifest.owner_kind, manifest.pid, manifest.mountpoint
            ),
        )
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
            protocol: "tidefs-live-owner-json-v1".to_string(),
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
    fn delegated_admin_payload_preserves_pool_uuid() {
        let request = LiveOwnerRequest {
            command: "dataset".to_string(),
            operation: "list".to_string(),
            pool: "tank".to_string(),
            pool_uuid: Some("0123456789abcdeffedcba9876543210".to_string()),
            json: true,
            args: serde_json::Value::Null,
        };

        let payload: serde_json::Value =
            serde_json::from_slice(&delegate_admin_payload(&request).unwrap()).unwrap();

        assert_eq!(
            payload.get("pool_uuid").and_then(serde_json::Value::as_str),
            Some("0123456789abcdeffedcba9876543210")
        );
    }

    #[test]
    fn pool_mount_request_fails_until_owner_can_mount() {
        let manifest = manifest();
        let request = LiveOwnerRequest {
            command: "pool".to_string(),
            operation: "mount".to_string(),
            pool: "tank".to_string(),
            pool_uuid: None,
            json: false,
            args: json!({
                "mountpoint": "/mnt/other",
                "dataset": "root",
                "read_only": true,
                "relatime": false,
            }),
        };

        let response = pool_mount_refused(&request, &manifest);

        assert!(!response.ok);
        assert_eq!(response.exit_code, 1);
        let error = response.error.expect("mount refusal should explain why");
        assert!(error.contains("already-imported pool 'tank'"));
        assert!(error.contains("live owner"));
        assert!(error.contains("/mnt/other"));
        assert!(error.contains("no secondary mount implementation"));
    }
}
