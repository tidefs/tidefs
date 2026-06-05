//! Userspace live-pool owner endpoint.
//!
//! This is the FUSE-session side of the imported-pool authority boundary:
//! pool-name commands talk to the runtime that owns cached state instead of
//! reopening devices or metadata directories behind it.

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
        mountpoint: config.mountpoint.display().to_string(),
        socket_path: socket_path.display().to_string(),
    };
    write_manifest(&manifest_path, &manifest)?;

    let thread_manifest = manifest.clone();
    let thread_socket_path = socket_path.clone();
    let thread_manifest_path = manifest_path.clone();
    let thread_shutdown = Arc::clone(&shutdown);
    let join = thread::spawn(move || {
        while !thread_shutdown.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    handle_client(stream, &thread_manifest, &engine);
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
        cleanup_endpoint(&thread_socket_path, &thread_manifest_path);
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
    json: bool,
}

#[derive(Debug, Serialize)]
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

fn handle_client(stream: UnixStream, manifest: &LiveOwnerManifest, engine: &LiveOwnerEngine) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let response = match reader.read_line(&mut line) {
        Ok(0) => LiveOwnerResponse::error(2, "empty live-owner request"),
        Ok(_) => match serde_json::from_str::<LiveOwnerRequest>(&line) {
            Ok(request) => dispatch_request(request, manifest, engine),
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

    match (request.command.as_str(), request.operation.as_str()) {
        ("pool", "status") => pool_status(request.json, manifest, engine),
        ("pool", "import") => already_owned("import", manifest, request.json),
        ("pool", "mount") => already_owned("mount", manifest, request.json),
        _ => LiveOwnerResponse::error(
            1,
            format!(
                "live owner '{}' does not yet implement tidefsctl {} {}",
                manifest.owner_kind, request.command, request.operation
            ),
        ),
    }
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
            "pool: {}\n  pool uuid:   {}\n  state:       Active\n  owner:       {} (pid {})\n  mountpoint:  {}\n  blocks:      total={} free={} avail={}\n  files:       total={} free={}",
            manifest.pool_name,
            manifest.pool_uuid,
            manifest.owner_kind,
            manifest.pid,
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

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
