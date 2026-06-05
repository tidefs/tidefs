//! Imported-pool live-owner routing helpers.
//!
//! A pool name is an identity for state already owned by a runtime, not a
//! filesystem path. Explicit storage arguments are not override handles once
//! a kernel, FUSE, or ublk runtime owns the imported pool.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;

#[derive(Debug, Clone)]
pub(crate) struct LivePoolRoute<'a> {
    pub(crate) command: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) pool_uuid: Option<[u8; 16]>,
    pub(crate) json: bool,
    pub(crate) args: serde_json::Value,
}

pub(crate) trait LivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> !;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MissingLivePoolOwnerClient;

impl LivePoolOwnerClient for MissingLivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> ! {
        match send_live_owner_request(&route) {
            Ok(()) => process::exit(0),
            Err(LiveOwnerRequestError::Unavailable(err)) => exit_unavailable(route, &err),
            Err(LiveOwnerRequestError::Owner { exit_code, message }) => {
                exit_owner_error(route, exit_code, &message)
            }
        }
    }
}

#[derive(Debug)]
enum LiveOwnerRequestError {
    Unavailable(String),
    Owner { exit_code: i32, message: String },
}

pub(crate) fn route(command: &str, operation: &str, pool: &str) -> ! {
    route_with_format(command, operation, pool, false)
}

pub(crate) fn route_with_format(command: &str, operation: &str, pool: &str, json: bool) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: None,
        json,
        args: serde_json::Value::Null,
    })
}

pub(crate) fn route_imported(command: &str, operation: &str, pool: &str, pool_uuid: [u8; 16]) -> ! {
    route_imported_with_format(command, operation, pool, pool_uuid, false)
}

pub(crate) fn route_imported_with_format(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    json: bool,
) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: Some(pool_uuid),
        json,
        args: serde_json::Value::Null,
    })
}

pub(crate) fn route_with_args(
    command: &str,
    operation: &str,
    pool: &str,
    args: serde_json::Value,
) -> ! {
    route_with_format_and_args(command, operation, pool, false, args)
}

pub(crate) fn route_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    json: bool,
    args: serde_json::Value,
) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: None,
        json,
        args,
    })
}

pub(crate) fn route_imported_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    json: bool,
    args: serde_json::Value,
) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: Some(pool_uuid),
        json,
        args,
    })
}

pub(crate) fn route_if_owned(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
) {
    route_if_owned_with_format_and_args(
        command,
        operation,
        pool,
        pool_uuid,
        active_label,
        false,
        serde_json::Value::Null,
    );
}

pub(crate) fn route_if_owned_with_format(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
    json: bool,
) {
    route_if_owned_with_format_and_args(
        command,
        operation,
        pool,
        pool_uuid,
        active_label,
        json,
        serde_json::Value::Null,
    );
}

pub(crate) fn route_if_owned_with_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
    args: serde_json::Value,
) {
    route_if_owned_with_format_and_args(
        command,
        operation,
        pool,
        pool_uuid,
        active_label,
        false,
        args,
    );
}

pub(crate) fn route_if_owned_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
    json: bool,
    args: serde_json::Value,
) {
    let root = pool_runtime_root();
    if active_label || owner_manifest_exists_by_uuid_at(&root, &pool_uuid) {
        route_imported_with_format_and_args(command, operation, pool, pool_uuid, json, args);
    }
    if owner_manifest_exists_by_pool_at(&root, pool) {
        route_with_format_and_args(command, operation, pool, json, args);
    }
}

fn exit_unavailable(route: LivePoolRoute<'_>, lookup_error: &str) -> ! {
    let command = route.command;
    let operation = route.operation;
    let pool = route.pool;
    eprintln!(
        "tidefsctl {command} {operation}: cannot reach live owner for imported pool '{pool}': {lookup_error}"
    );
    if let Some(pool_uuid) = route.pool_uuid {
        eprintln!(
            "tidefsctl {command} {operation}: devices identify imported pool uuid {}",
            hex_uuid(&pool_uuid)
        );
    }
    eprintln!(
        "tidefsctl {command} {operation}: live pool state is cached and owned by the active runtime"
    );
    eprintln!(
        "tidefsctl {command} {operation}: route through the kernel UAPI in kernel mode, or the FUSE/ublk daemon owner in userspace mode"
    );
    eprintln!(
        "tidefsctl {command} {operation}: use --devices or --backing-dir only for offline, discovery, import, or not-yet-imported work"
    );
    process::exit(1);
}

fn exit_owner_error(route: LivePoolRoute<'_>, exit_code: i32, message: &str) -> ! {
    let command = route.command;
    let operation = route.operation;
    let pool = route.pool;
    eprintln!(
        "tidefsctl {command} {operation}: live owner for imported pool '{pool}' refused request: {message}"
    );
    eprintln!(
        "tidefsctl {command} {operation}: refusing to fall back to direct device access for imported pool state"
    );
    process::exit(if exit_code == 0 { 1 } else { exit_code });
}

fn send_live_owner_request(route: &LivePoolRoute<'_>) -> Result<(), LiveOwnerRequestError> {
    let manifest = find_live_owner_manifest(route)?;
    let socket_path = manifest_socket_path(&manifest)?;
    let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("connect {}: {err}", socket_path.display()))
    })?;
    let request = serde_json::json!({
        "command": route.command,
        "operation": route.operation,
        "pool": route.pool,
        "json": route.json,
        "args": &route.args,
    });
    stream
        .write_all(request.to_string().as_bytes())
        .map_err(|err| {
            LiveOwnerRequestError::Unavailable(format!("write live-owner request: {err}"))
        })?;
    stream.write_all(b"\n").map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("finish live-owner request: {err}"))
    })?;

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("read live-owner response: {err}"))
    })?;
    if line.trim().is_empty() {
        return Err(LiveOwnerRequestError::Owner {
            exit_code: 2,
            message: "empty live-owner response".to_string(),
        });
    }
    let response: serde_json::Value =
        serde_json::from_str(&line).map_err(|err| LiveOwnerRequestError::Owner {
            exit_code: 2,
            message: format!("decode live-owner response: {err}"),
        })?;
    let ok = response
        .get("ok")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if ok {
        if route.json {
            if let Some(value) = response.get("json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(value).map_err(|err| {
                        LiveOwnerRequestError::Owner {
                            exit_code: 2,
                            message: format!("format live-owner JSON: {err}"),
                        }
                    })?
                );
            } else if let Some(text) = response.get("text").and_then(serde_json::Value::as_str) {
                println!("{text}");
            }
        } else if let Some(text) = response.get("text").and_then(serde_json::Value::as_str) {
            println!("{text}");
        } else if let Some(value) = response.get("json") {
            println!(
                "{}",
                serde_json::to_string_pretty(value).map_err(|err| {
                    LiveOwnerRequestError::Owner {
                        exit_code: 2,
                        message: format!("format live-owner JSON: {err}"),
                    }
                })?
            );
        }
        Ok(())
    } else {
        let message = response
            .get("error")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("live owner returned an error");
        let exit_code = response
            .get("exit_code")
            .and_then(serde_json::Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or(1);
        Err(LiveOwnerRequestError::Owner {
            exit_code,
            message: message.to_string(),
        })
    }
}

fn find_live_owner_manifest(
    route: &LivePoolRoute<'_>,
) -> Result<serde_json::Value, LiveOwnerRequestError> {
    if let Some(pool_uuid) = route.pool_uuid {
        let manifest_path = owner_manifest_path(&pool_runtime_root(), &pool_uuid);
        return read_manifest(&manifest_path);
    }

    let root = pool_runtime_root();
    let entries = std::fs::read_dir(&root).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("read {}: {err}", root.display()))
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| {
            LiveOwnerRequestError::Unavailable(format!("read {} entry: {err}", root.display()))
        })?;
        let path = entry.path().join("owner.json");
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if manifest
            .get("pool_name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == route.pool)
        {
            return Ok(manifest);
        }
    }
    Err(LiveOwnerRequestError::Unavailable(format!(
        "no live owner manifest for pool '{pool}'",
        pool = route.pool
    )))
}

fn owner_manifest_exists_by_uuid_at(root: &Path, uuid: &[u8; 16]) -> bool {
    match owner_manifest_path(root, uuid).try_exists() {
        Ok(exists) => exists,
        Err(_) => true,
    }
}

fn owner_manifest_exists_by_pool_at(root: &Path, pool: &str) -> bool {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return true,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => return true,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => return true,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if manifest
            .get("pool_name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == pool)
        {
            return true;
        }
    }
    false
}

fn owner_manifest_path(root: &Path, uuid: &[u8; 16]) -> PathBuf {
    root.join(hex_uuid(uuid)).join("owner.json")
}

fn read_manifest(path: &Path) -> Result<serde_json::Value, LiveOwnerRequestError> {
    let text = std::fs::read_to_string(path).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!(
            "read live owner manifest {}: {err}",
            path.display()
        ))
    })?;
    serde_json::from_str(&text).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("decode {}: {err}", path.display()))
    })
}

fn manifest_socket_path(manifest: &serde_json::Value) -> Result<PathBuf, LiveOwnerRequestError> {
    manifest
        .get("socket_path")
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
        .ok_or_else(|| {
            LiveOwnerRequestError::Unavailable("live owner manifest has no socket_path".to_string())
        })
}

fn pool_runtime_root() -> PathBuf {
    PathBuf::from("/run/tidefs/pools")
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_manifest_exists_by_uuid_when_manifest_path_exists() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(&manifest_path, b"not json").unwrap();

        assert!(owner_manifest_exists_by_uuid_at(dir.path(), &uuid));
    }

    #[test]
    fn owner_manifest_exists_by_pool_when_manifest_names_pool() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x24; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "socket_path": "/run/tidefs/pools/test/owner.sock",
            })
            .to_string(),
        )
        .unwrap();

        assert!(owner_manifest_exists_by_pool_at(dir.path(), "tank"));
        assert!(!owner_manifest_exists_by_pool_at(dir.path(), "other"));
    }

    #[test]
    fn owner_manifest_absent_when_runtime_root_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");

        assert!(!owner_manifest_exists_by_pool_at(&missing, "tank"));
        assert!(!owner_manifest_exists_by_uuid_at(&missing, &[0x11; 16]));
    }
}
