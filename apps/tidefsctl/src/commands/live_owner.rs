// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Imported-pool live-owner routing helpers.
//!
//! A pool name is an identity for state already owned by a runtime, not a
//! filesystem path. Explicit storage arguments are not override handles once
//! a kernel, FUSE, or ublk runtime owns the imported pool. The live owner
//! interface is the reachable kernel/daemon endpoint, not a stale runtime
//! manifest file. Cached ACTIVE label state is not the live interface either,
//! but it is enough evidence to fail closed until an owner handles the request
//! or the operator enters a recovery path that creates/cleans that owner state.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process;

use tidefs_device_removal::admission::{
    validate_live_owner_response, DeviceRemovalAdmissionRequest, DEVICE_REMOVAL_AUTHORITY_KIND,
};
use tidefs_vfs_engine::{
    LivePoolAdminArg, LivePoolAdminArgs, LivePoolAdminCommand, LivePoolAdminError,
    LivePoolAdminOutput, LivePoolAdminRequest, LivePoolAdminResponse, LivePoolAdminResponseBody,
};

#[derive(Debug, Clone)]
pub(crate) struct LivePoolRoute<'a> {
    pub(crate) command: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) pool_uuid: Option<[u8; 16]>,
    pub(crate) json: bool,
    pub(crate) args: LivePoolAdminArgs,
}

pub(crate) trait LivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> !;
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ImportedBackingDirOwner {
    pub(crate) pool: String,
    pub(crate) pool_uuid: [u8; 16],
    pub(crate) reachable: bool,
}

impl ImportedBackingDirOwner {
    pub(crate) fn pool_uuid_hex(&self) -> String {
        hex_uuid(&self.pool_uuid)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum ImportedBackingDirDecision {
    Exact(ImportedBackingDirOwner),
    Foreign(ImportedBackingDirOwner),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MissingLivePoolOwnerClient;

impl LivePoolOwnerClient for MissingLivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> ! {
        match send_live_owner_request(&route) {
            Ok(()) => process::exit(0),
            Err(LiveOwnerRequestError::Unavailable(err)) => exit_unavailable(route, &err),
            Err(LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            }) => exit_owner_error(route, exit_code, &message, detail.as_ref()),
        }
    }
}

#[derive(Debug)]
enum LiveOwnerRequestError {
    Unavailable(String),
    Owner {
        exit_code: i32,
        message: String,
        detail: Option<serde_json::Value>,
    },
}

pub(crate) fn route_with_format(command: &str, operation: &str, pool: &str, json: bool) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: None,
        json,
        args: LivePoolAdminArgs::default(),
    })
}

pub(crate) fn route_with_args(
    command: &str,
    operation: &str,
    pool: &str,
    args: LivePoolAdminArgs,
) -> ! {
    route_with_format_and_args(command, operation, pool, false, args)
}

pub(crate) fn route_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    json: bool,
    args: LivePoolAdminArgs,
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

pub(crate) fn route_if_owner_exists_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    json: bool,
    args: LivePoolAdminArgs,
) {
    let root = pool_runtime_root();
    if owner_interface_reachable_by_pool_at(&root, pool) {
        route_with_format_and_args(command, operation, pool, json, args);
    }
    if owner_record_cached_by_pool_at(&root, pool) {
        refuse_cached_without_owner(command, operation, pool, None, json);
    }
}

pub(crate) fn route_if_owner_exists_for_pool_backing_dir_with_args(
    command: &str,
    operation: &str,
    pool: &str,
    backing_dir: &Path,
    args: LivePoolAdminArgs,
) {
    let root = pool_runtime_root();
    match imported_backing_dir_decision_at(&root, pool, backing_dir) {
        Some(ImportedBackingDirDecision::Exact(owner)) if owner.reachable => {
            route_imported_with_format_and_args(
                command,
                operation,
                pool,
                owner.pool_uuid,
                false,
                args,
            );
        }
        Some(ImportedBackingDirDecision::Exact(owner)) => {
            refuse_cached_without_owner(command, operation, pool, Some(owner.pool_uuid), false);
        }
        Some(ImportedBackingDirDecision::Foreign(owner)) => {
            refuse_foreign_imported_backing_dir(command, operation, pool, backing_dir, &owner);
        }
        None => {}
    }
}

pub(crate) fn route_if_owner_exists_for_backing_dir_with_args(
    command: &str,
    operation: &str,
    backing_dir: &Path,
    args: LivePoolAdminArgs,
) {
    let root = pool_runtime_root();
    match imported_owner_by_backing_dir_at(&root, backing_dir) {
        Some(owner) if owner.reachable => {
            route_imported_with_format_and_args(
                command,
                operation,
                &owner.pool,
                owner.pool_uuid,
                false,
                args,
            );
        }
        Some(owner) => {
            refuse_cached_without_owner(
                command,
                operation,
                &owner.pool,
                Some(owner.pool_uuid),
                false,
            );
        }
        None => {}
    }
}

pub(crate) fn route_or_refuse_active_for_uuid_with_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
    args: LivePoolAdminArgs,
) {
    route_or_refuse_active_for_uuid_with_format_and_args(
        command,
        operation,
        pool,
        pool_uuid,
        active_label,
        false,
        args,
    );
}

pub(crate) fn route_or_refuse_active_for_uuid_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    active_label: bool,
    json: bool,
    args: LivePoolAdminArgs,
) {
    let root = pool_runtime_root();
    if owner_interface_reachable_for_uuid_at(&root, pool, &pool_uuid) {
        route_imported_with_format_and_args(command, operation, pool, pool_uuid, json, args);
    }
    if owner_record_cached_for_uuid_at(&root, pool, &pool_uuid) {
        refuse_cached_without_owner(command, operation, pool, Some(pool_uuid), json);
    }
    if active_label {
        refuse_active_without_owner(command, operation, pool, pool_uuid, json);
    }
}

pub(crate) fn route_imported_with_format_and_args(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: [u8; 16],
    json: bool,
    args: LivePoolAdminArgs,
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

pub(crate) fn live_admin_args(
    entries: impl IntoIterator<Item = (&'static str, LivePoolAdminArg)>,
) -> LivePoolAdminArgs {
    LivePoolAdminArgs(
        entries
            .into_iter()
            .map(|(key, value)| (key.to_string(), value))
            .collect(),
    )
}

pub(crate) fn live_admin_optional_string(value: Option<String>) -> LivePoolAdminArg {
    value
        .map(LivePoolAdminArg::String)
        .unwrap_or(LivePoolAdminArg::Null)
}

pub(crate) fn live_admin_optional_u64(value: Option<u64>) -> LivePoolAdminArg {
    value
        .map(LivePoolAdminArg::U64)
        .unwrap_or(LivePoolAdminArg::Null)
}

/// Route a status command to the live owner if reachable. Returns true
/// if the request was routed (the process exits inside the route),
/// returns false if no live owner was found so the caller can produce
/// a source-classified refusal.
pub(crate) fn route_status_if_owner_exists(
    command: &str,
    operation: &str,
    pool: &str,
    json: bool,
) -> bool {
    let root = pool_runtime_root();
    if owner_interface_reachable_by_pool_at(&root, pool) {
        route_with_format(command, operation, pool, json);
    }
    false
}

/// Refuse a cluster or device status request with a source-classified
/// message that states no live status evidence was obtained. Cached
/// metadata is identified as non-authoritative.
pub(crate) fn refuse_no_live_status_evidence(
    command: &str,
    operation: &str,
    pool: &str,
    json: bool,
) -> ! {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&no_live_status_refusal_json(command, operation, pool))
                .unwrap()
        );
    } else {
        for line in no_live_status_refusal_lines(command, operation, pool) {
            eprintln!("{line}");
        }
    }
    process::exit(1);
}

fn no_live_status_refusal_json(command: &str, operation: &str, pool: &str) -> serde_json::Value {
    let unavailable = super::classification::StatusSource::UnavailableLiveOwner.label();
    let unsupported = super::classification::StatusSource::UnsupportedLocalMode.label();
    serde_json::json!({
        "ok": false,
        "command": command,
        "operation": operation,
        "pool_name": pool,
        "source_classification": unavailable,
        "source:status": unavailable,
        "local_mode_classification": unsupported,
        "error": "no live status evidence obtained; cached local metadata is non-authoritative for live cluster/device state",
        "recovery": "start or repair the kernel UAPI or userspace daemon that owns this pool; do not treat cached metadata as live truth",
    })
}

fn no_live_status_refusal_lines(command: &str, operation: &str, pool: &str) -> Vec<String> {
    vec![
        format!("tidefsctl {command} {operation}: no live status evidence obtained for pool '{pool}'"),
        format!(
            "tidefsctl {command} {operation}: [{}] no reachable live owner",
            super::classification::StatusSource::UnavailableLiveOwner.label()
        ),
        format!(
            "tidefsctl {command} {operation}: [{}] local/offline status mode is unsupported for live cluster/device state",
            super::classification::StatusSource::UnsupportedLocalMode.label()
        ),
        format!(
            "tidefsctl {command} {operation}: cached local metadata, command-line parse results, and static configuration are non-authoritative for live cluster/device state"
        ),
        format!(
            "tidefsctl {command} {operation}: refusing to present cached data as live status truth"
        ),
    ]
}
fn refuse_active_without_owner(
    command: &str,
    operation: &str,
    pool: &str,

    pool_uuid: [u8; 16],
    json: bool,
) -> ! {
    let pool_uuid_hex = hex_uuid(&pool_uuid);
    if json {
        let out = serde_json::json!({
            "ok": false,
            "command": command,
            "operation": operation,
            "pool_name": pool,
            "pool_uuid": pool_uuid_hex,
            "state": "ACTIVE",
            "owner_required": true,
            "source:status": super::classification::StatusSource::UnsupportedOrOffline.label(),
            "error": "devices identify an imported pool but no live owner interface is reachable",
            "recovery": "repair or restart the kernel UAPI or userspace daemon owner before operating on live state; do not open cached imported-pool state directly",
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        eprintln!(
            "tidefsctl {command} {operation}: devices identify imported pool '{pool}' uuid {pool_uuid_hex}, but no live owner interface is reachable"
        );
        eprintln!(
            "tidefsctl {command} {operation}: [source:unsupported-or-offline] no reachable live owner; device labels report ACTIVE state"
        );
        eprintln!(
            "tidefsctl {command} {operation}: imported pool state is cached and must be owned by the kernel UAPI or userspace daemon"
        );
        eprintln!(
            "tidefsctl {command} {operation}: refusing direct device access; repair or restart the owner before live-state operations"
        );
    }
    process::exit(1);
}

fn refuse_cached_without_owner(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: Option<[u8; 16]>,
    json: bool,
) -> ! {
    if json {
        let out = cached_without_owner_json(command, operation, pool, pool_uuid);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        for line in cached_without_owner_lines(command, operation, pool, pool_uuid) {
            eprintln!("{line}");
        }
    }
    process::exit(1);
}

fn cached_without_owner_json(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: Option<[u8; 16]>,
) -> serde_json::Value {
    let mut out = serde_json::json!({
        "ok": false,
        "command": command,
        "operation": operation,
        "pool_name": pool,
        "cached_import_state": true,
        "owner_required": true,
        "source:status": super::classification::StatusSource::CachedLocalMetadata.label(),
        "error": "cached imported-pool state exists but no live owner interface is reachable",
        "recovery": "start or repair the kernel UAPI or userspace daemon that owns this imported pool; do not open the cached state directly",
    });
    if let Some(pool_uuid) = pool_uuid {
        out["pool_uuid"] = serde_json::Value::String(hex_uuid(&pool_uuid));
    }
    annotate_device_removal_authority_json(command, operation, &mut out);
    out
}

fn cached_without_owner_lines(
    command: &str,
    operation: &str,
    pool: &str,
    pool_uuid: Option<[u8; 16]>,
) -> Vec<String> {
    let mut lines = vec![format!(
        "tidefsctl {command} {operation}: cached imported-pool state exists for '{pool}', but no live owner interface is reachable"
    )];
    lines.push(format!(
        "tidefsctl {command} {operation}: [source:cached-local-metadata] cached owner record exists but no reachable live owner interface"
    ));
    if let Some(pool_uuid) = pool_uuid {
        lines.push(format!(
            "tidefsctl {command} {operation}: cached pool uuid {}",
            hex_uuid(&pool_uuid)
        ));
    }
    if let Some(line) = device_removal_authority_line(command, operation, None) {
        lines.push(line);
    }
    lines.push(format!(
        "tidefsctl {command} {operation}: live state must be handled by the kernel UAPI or userspace daemon that owns the import"
    ));
    lines.push(format!(
        "tidefsctl {command} {operation}: refusing direct access to cached imported-pool state"
    ));
    lines
}

fn refuse_foreign_imported_backing_dir(
    command: &str,
    operation: &str,
    requested_pool: &str,
    backing_dir: &Path,
    owner: &ImportedBackingDirOwner,
) -> ! {
    let state = if owner.reachable {
        "reachable live owner"
    } else {
        "cached owner record"
    };
    eprintln!(
        "tidefsctl {command} {operation}: {} is imported-pool state for pool '{}' uuid {}, not requested pool '{requested_pool}' ({state})",
        backing_dir.display(),
        owner.pool,
        owner.pool_uuid_hex(),
    );
    eprintln!(
        "tidefsctl {command} {operation}: [source:cached-local-metadata] backing dir belongs to a different pool; refusing to use as exported/offline storage"
    );
    eprintln!(
        "tidefsctl {command} {operation}: live state must be handled by the kernel UAPI or userspace daemon that owns pool '{}'",
        owner.pool
    );
    eprintln!(
        "tidefsctl {command} {operation}: refusing to treat cached imported-pool state as exported/offline storage"
    );
    process::exit(1);
}

fn exit_unavailable(route: LivePoolRoute<'_>, lookup_error: &str) -> ! {
    let command = route.command;
    let operation = route.operation;
    let pool = route.pool;
    if route.json {
        let mut out = serde_json::json!({
            "ok": false,
            "command": command,
            "operation": operation,
            "pool_name": pool,
            "owner_required": true,
            "source:status": super::classification::StatusSource::UnsupportedOrOffline.label(),
            "error": format!("cannot use a live-owner interface for imported pool '{pool}': {lookup_error}"),
            "recovery": "repair or restart the kernel UAPI or userspace daemon owner before operating on live state; do not open cached imported-pool state directly",
        });
        if let Some(pool_uuid) = route.pool_uuid {
            out["pool_uuid"] = serde_json::Value::String(hex_uuid(&pool_uuid));
        }
        annotate_device_removal_authority_json(command, operation, &mut out);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        process::exit(1);
    }
    eprintln!(
        "tidefsctl {command} {operation}: cannot use a live-owner interface for imported pool '{pool}': {lookup_error}"
    );
    eprintln!(
        "tidefsctl {command} {operation}: [source:unsupported-or-offline] no reachable live owner interface"
    );
    if let Some(pool_uuid) = route.pool_uuid {
        eprintln!(
            "tidefsctl {command} {operation}: request identified pool uuid {}",
            hex_uuid(&pool_uuid)
        );
    }
    if let Some(line) = device_removal_authority_line(command, operation, route_device_path(&route))
    {
        eprintln!("{line}");
    }
    eprintln!(
        "tidefsctl {command} {operation}: cached imported-pool state is evidence, not an authority interface"
    );
    eprintln!(
        "tidefsctl {command} {operation}: live state must be requested through the kernel UAPI client in kernel mode, or the FUSE/ublk daemon owner in userspace mode"
    );
    eprintln!(
        "tidefsctl {command} {operation}: use explicit --devices only for offline, discovery, owner-creating import-and-mount, or not-yet-imported pool media"
    );
    process::exit(1);
}

fn exit_owner_error(
    route: LivePoolRoute<'_>,
    exit_code: i32,
    message: &str,
    detail: Option<&serde_json::Value>,
) -> ! {
    let command = route.command;
    let operation = route.operation;
    let pool = route.pool;
    if route.json {
        let mut out = detail.map_or_else(
            || {
                serde_json::json!({
                    "ok": false,
                    "command": command,
                    "operation": operation,
                    "pool_name": pool,
                    "owner_required": true,
                    "error": message,
                    "recovery": "use the live owner response as authoritative; tidefsctl will not fall back to direct device access for imported pool state",
                })
            },
            |detail| live_owner_error_detail_json(&route, message, detail),
        );
        if let Some(pool_uuid) = route.pool_uuid {
            out["pool_uuid"] = serde_json::Value::String(hex_uuid(&pool_uuid));
        }
        annotate_live_owner_status_refusal_json(&route, detail, &mut out);
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
        process::exit(if exit_code == 0 { 1 } else { exit_code });
    }
    for line in live_owner_status_refusal_human_lines(&route, detail) {
        eprintln!("{line}");
    }
    eprintln!(
        "tidefsctl {command} {operation}: live owner for imported pool '{pool}' refused request: {message}"
    );
    eprintln!(
        "tidefsctl {command} {operation}: refusing to fall back to direct device access for imported pool state"
    );
    process::exit(if exit_code == 0 { 1 } else { exit_code });
}

fn live_owner_error_detail_json(
    route: &LivePoolRoute<'_>,
    message: &str,
    detail: &serde_json::Value,
) -> serde_json::Value {
    let mut out = match detail {
        serde_json::Value::Object(_) => detail.clone(),
        other => serde_json::json!({
            "detail": other,
        }),
    };
    let Some(object) = out.as_object_mut() else {
        return serde_json::json!({
            "ok": false,
            "command": route.command,
            "operation": route.operation,
            "pool_name": route.pool,
            "owner_required": true,
            "error": message,
            "detail": detail,
        });
    };
    object.insert("ok".to_string(), serde_json::Value::Bool(false));
    object
        .entry("command".to_string())
        .or_insert_with(|| serde_json::Value::String(route.command.to_string()));
    object
        .entry("operation".to_string())
        .or_insert_with(|| serde_json::Value::String(route.operation.to_string()));
    object
        .entry("pool_name".to_string())
        .or_insert_with(|| serde_json::Value::String(route.pool.to_string()));
    object
        .entry("owner_required".to_string())
        .or_insert(serde_json::Value::Bool(true));
    object
        .entry("error".to_string())
        .or_insert_with(|| serde_json::Value::String(message.to_string()));
    out
}

fn send_live_owner_request(route: &LivePoolRoute<'_>) -> Result<(), LiveOwnerRequestError> {
    send_live_owner_request_at(&pool_runtime_root(), route)
}

fn send_live_owner_request_at(
    root: &Path,
    route: &LivePoolRoute<'_>,
) -> Result<(), LiveOwnerRequestError> {
    let request = live_owner_request(route)?;
    let manifest = find_live_owner_manifest_at(root, route)?;
    let socket_path = manifest_socket_endpoint(&manifest, route)?;
    let mut stream = UnixStream::connect(&socket_path).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("connect {}: {err}", socket_path.display()))
    })?;
    stream
        .write_all(
            serde_json::to_string(&request)
                .map_err(|err| LiveOwnerRequestError::Owner {
                    exit_code: 2,
                    message: format!("encode live-owner request: {err}"),
                    detail: None,
                })?
                .as_bytes(),
        )
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
        return Err(live_admin_error_to_request_error(
            LivePoolAdminError::malformed("empty live-owner response"),
        ));
    }
    let response =
        decode_live_pool_admin_response(&line).map_err(live_admin_error_to_request_error)?;
    validate_live_owner_response_envelope(&response)?;
    match response.body {
        LivePoolAdminResponseBody::BytesHex {
            bytes_hex,
            bytes: declared_bytes,
        } => {
            let bytes = decode_live_owner_hex(&bytes_hex)?;
            if bytes.len() != declared_bytes {
                return Err(live_admin_error_to_request_error(
                    LivePoolAdminError::malformed(format!(
                        "live-owner byte response length mismatch: declared {declared_bytes}, decoded {}",
                        bytes.len()
                    )),
                ));
            }
            let response_json = live_owner_bytes_json(&bytes_hex, declared_bytes);
            validate_required_owner_evidence(route, &response_json)?;
            if route.json {
                let out = serde_json::json!({
                    "ok": true,
                    "bytes": bytes.len(),
                    "bytes_hex": bytes_hex,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&out).map_err(|err| {
                        LiveOwnerRequestError::Owner {
                            exit_code: 2,
                            message: format!("format live-owner bytes JSON: {err}"),
                            detail: None,
                        }
                    })?
                );
            } else {
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all(&bytes)
                    .map_err(|err| LiveOwnerRequestError::Owner {
                        exit_code: 1,
                        message: format!("write live-owner byte response to stdout: {err}"),
                        detail: None,
                    })?;
            }
            Ok(())
        }
        LivePoolAdminResponseBody::MachineJson(machine_json) => {
            let mut value = parse_live_owner_machine_json(&machine_json)?;
            validate_required_owner_evidence(route, &value)?;
            if route.json {
                annotate_live_owner_status_json(route, &mut value);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).map_err(|err| {
                        LiveOwnerRequestError::Owner {
                            exit_code: 2,
                            message: format!("format live-owner JSON: {err}"),
                            detail: None,
                        }
                    })?
                );
            } else {
                annotate_live_owner_status_json(route, &mut value);
                for line in live_owner_machine_json_human_lines(route, &value) {
                    println!("{line}");
                }
            }
            Ok(())
        }
        LivePoolAdminResponseBody::Text(text) => {
            let response_json = live_owner_status_text_json(route, &text);
            validate_required_owner_evidence(route, &response_json)?;
            if route.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&response_json).map_err(|err| {
                        LiveOwnerRequestError::Owner {
                            exit_code: 2,
                            message: format!("format live-owner JSON: {err}"),
                            detail: None,
                        }
                    })?
                );
            } else {
                print_live_owner_status_classification(route);
                println!("{text}");
            }
            Ok(())
        }
        LivePoolAdminResponseBody::Empty => {
            let response_json = live_owner_status_text_json(route, "");
            validate_required_owner_evidence(route, &response_json)?;
            if route.json && is_status_route(route) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&response_json).map_err(|err| {
                        LiveOwnerRequestError::Owner {
                            exit_code: 2,
                            message: format!("format live-owner JSON: {err}"),
                            detail: None,
                        }
                    })?
                );
            } else {
                print_live_owner_status_classification(route);
            }
            Ok(())
        }
        LivePoolAdminResponseBody::Error {
            message,
            machine_json,
        } => Err(LiveOwnerRequestError::Owner {
            exit_code: response.exit_code,
            message,
            detail: machine_json
                .as_deref()
                .map(parse_live_owner_machine_json)
                .transpose()?,
        }),
    }
}

fn decode_live_pool_admin_response(
    line: &str,
) -> Result<LivePoolAdminResponse, LivePoolAdminError> {
    let value: serde_json::Value = serde_json::from_str(line).map_err(|err| {
        LivePoolAdminError::malformed(format!("decode live-owner response: {err}"))
    })?;
    let version = decode_live_pool_admin_response_version(&value)?;
    if version != tidefs_vfs_engine::LIVE_POOL_ADMIN_PROTOCOL_VERSION {
        return Err(LivePoolAdminError::unsupported_response_version(version));
    }

    serde_json::from_value(value)
        .map_err(|err| LivePoolAdminError::malformed(format!("decode live-owner response: {err}")))
}

fn decode_live_pool_admin_response_version(
    value: &serde_json::Value,
) -> Result<u16, LivePoolAdminError> {
    let Some(version) = value.get("version") else {
        return Err(LivePoolAdminError::malformed(
            "decode live-owner response: missing version",
        ));
    };
    let Some(version) = version
        .as_u64()
        .and_then(|version| u16::try_from(version).ok())
    else {
        return Err(LivePoolAdminError::malformed(
            "decode live-owner response: malformed version",
        ));
    };

    Ok(version)
}

fn validate_live_owner_response_envelope(
    response: &LivePoolAdminResponse,
) -> Result<(), LiveOwnerRequestError> {
    let malformed = || {
        live_admin_error_to_request_error(LivePoolAdminError::malformed(
            "live-owner response exit code is inconsistent with response body",
        ))
    };

    match &response.body {
        LivePoolAdminResponseBody::Error { .. } if response.exit_code == 0 => Err(malformed()),
        LivePoolAdminResponseBody::Error { .. } => Ok(()),
        _ if response.exit_code != 0 => Err(malformed()),
        _ => Ok(()),
    }
}

fn validate_required_owner_evidence(
    route: &LivePoolRoute<'_>,
    response: &serde_json::Value,
) -> Result<(), LiveOwnerRequestError> {
    let Some(request) = device_removal_admission_request(route) else {
        return Ok(());
    };
    validate_live_owner_response(&request, response)
        .map(|_| ())
        .map_err(|err| LiveOwnerRequestError::Owner {
            exit_code: 1,
            message: err.to_string(),
            detail: None,
        })
}

fn parse_live_owner_machine_json(value: &str) -> Result<serde_json::Value, LiveOwnerRequestError> {
    serde_json::from_str(value).map_err(|err| LiveOwnerRequestError::Owner {
        exit_code: 2,
        message: format!("decode live-owner machine JSON: {err}"),
        detail: None,
    })
}

fn live_owner_bytes_json(bytes_hex: &str, bytes: usize) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "bytes": bytes,
        "bytes_hex": bytes_hex,
    })
}

fn device_removal_admission_request(
    route: &LivePoolRoute<'_>,
) -> Option<DeviceRemovalAdmissionRequest> {
    if route.command != "device" || route.operation != "remove" {
        return None;
    }
    let device_path = route
        .args
        .0
        .get("device_path")
        .and_then(|value| match value {
            LivePoolAdminArg::String(value) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or_default();
    Some(DeviceRemovalAdmissionRequest::new(route.pool, device_path))
}

fn is_device_removal_route(command: &str, operation: &str) -> bool {
    command == "device" && operation == "remove"
}

fn route_device_path<'route>(route: &'route LivePoolRoute<'_>) -> Option<&'route str> {
    route
        .args
        .0
        .get("device_path")
        .and_then(|value| match value {
            LivePoolAdminArg::String(value) => Some(value.as_str()),
            _ => None,
        })
}

fn annotate_device_removal_authority_json(
    command: &str,
    operation: &str,
    out: &mut serde_json::Value,
) {
    if !is_device_removal_route(command, operation) {
        return;
    }
    out["required_authority"] =
        serde_json::Value::String(DEVICE_REMOVAL_AUTHORITY_KIND.to_string());
    out["authority_error"] = serde_json::Value::String(
        "device removal requires committed evacuation receipt authority from a reachable live owner"
            .to_string(),
    );
}

fn device_removal_authority_line(
    command: &str,
    operation: &str,
    device_path: Option<&str>,
) -> Option<String> {
    if !is_device_removal_route(command, operation) {
        return None;
    }
    let target = device_path
        .filter(|value| !value.is_empty())
        .map(|value| format!(" for device '{value}'"))
        .unwrap_or_default();
    Some(format!(
        "tidefsctl {command} {operation}: missing committed evacuation receipt authority{target}; cached imported-pool state is not removal authority"
    ))
}

fn is_status_route(route: &LivePoolRoute<'_>) -> bool {
    route.operation == "status" && matches!(route.command, "pool" | "cluster" | "device")
}

fn live_owner_status_scope(route: &LivePoolRoute<'_>) -> Option<&'static str> {
    matches!((route.command, route.operation), ("pool", "status")).then_some("local-pool")
}

fn is_exact_live_owner_status_refusal(
    route: &LivePoolRoute<'_>,
    detail: Option<&serde_json::Value>,
) -> bool {
    if !matches!((route.command, route.operation), ("pool", "status")) {
        return false;
    }
    let Some(detail) = detail.and_then(serde_json::Value::as_object) else {
        return false;
    };
    detail.get("kind").and_then(serde_json::Value::as_str) == Some("unsupported_command")
        && detail.get("command").and_then(serde_json::Value::as_str) == Some("pool")
        && detail.get("operation").and_then(serde_json::Value::as_str) == Some("status")
}

fn annotate_live_owner_status_refusal_json(
    route: &LivePoolRoute<'_>,
    detail: Option<&serde_json::Value>,
    value: &mut serde_json::Value,
) {
    if !is_exact_live_owner_status_refusal(route, detail) {
        return;
    }
    let source = super::classification::StatusSource::LiveOwner.label();
    let Some(object) = value.as_object_mut() else {
        return;
    };
    object.insert(
        "source_classification".to_string(),
        serde_json::Value::String(source.to_string()),
    );
    object.insert(
        "source:status".to_string(),
        serde_json::Value::String(source.to_string()),
    );
    object.insert(
        "owner_response".to_string(),
        serde_json::Value::String("refused".to_string()),
    );
    object.insert(
        "status_facts_accepted".to_string(),
        serde_json::Value::Bool(false),
    );
    if let Some(scope) = live_owner_status_scope(route) {
        object.insert(
            "scope".to_string(),
            serde_json::Value::String(scope.to_string()),
        );
    }
}

fn live_owner_status_refusal_human_lines(
    route: &LivePoolRoute<'_>,
    detail: Option<&serde_json::Value>,
) -> Vec<String> {
    if !is_exact_live_owner_status_refusal(route, detail) {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "path:       tidefsctl {} {}",
        route.command, route.operation
    )];
    if let Some(scope) = live_owner_status_scope(route) {
        lines.push(format!("scope:      {scope}"));
    }
    lines.push("response:   refused".to_string());
    lines.push(format!(
        "source_classification: {}",
        super::classification::StatusSource::LiveOwner.label()
    ));
    lines.push(format!(
        "tidefsctl {} {}: no {} status facts were accepted",
        route.command, route.operation, route.command
    ));
    lines
}

fn annotate_live_owner_status_json(route: &LivePoolRoute<'_>, value: &mut serde_json::Value) {
    if !is_status_route(route) {
        return;
    }

    let source = super::classification::StatusSource::LiveOwner.label();
    if !value.is_object() {
        let original = std::mem::take(value);
        *value = serde_json::json!({"ok": true, "value": original});
    }
    let Some(object) = value.as_object_mut() else {
        return;
    };
    object.insert(
        "source_classification".to_string(),
        serde_json::Value::String(source.to_string()),
    );
    if let Some(scope) = live_owner_status_scope(route) {
        object.insert(
            "scope".to_string(),
            serde_json::Value::String(scope.to_string()),
        );
    }
}

fn live_owner_status_text_json(route: &LivePoolRoute<'_>, text: &str) -> serde_json::Value {
    if is_status_route(route) {
        let source = super::classification::StatusSource::LiveOwner.label();
        let mut value = serde_json::json!({
            "ok": true,
            "command": route.command,
            "operation": route.operation,
            "pool_name": route.pool,
            "source_classification": source,
            "text": text,
        });
        if let Some(scope) = live_owner_status_scope(route) {
            value["scope"] = serde_json::Value::String(scope.to_string());
        }
        value
    } else {
        serde_json::json!({
            "ok": true,
            "text": text,
        })
    }
}

fn live_owner_machine_json_human_lines(
    route: &LivePoolRoute<'_>,
    value: &serde_json::Value,
) -> Vec<String> {
    let mut lines = live_owner_status_human_lines(route);

    if let Some(object) = value.as_object() {
        for key in ["text", "message", "error"] {
            if let Some(text) = object.get(key).and_then(serde_json::Value::as_str) {
                let message_lines: Vec<String> = text
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .map(ToOwned::to_owned)
                    .collect();
                if !message_lines.is_empty() {
                    lines.extend(message_lines);
                    return lines;
                }
            }
        }
    }

    lines.push(format!(
        "tidefsctl {} {}: live owner returned machine JSON; rerun with --json for details",
        route.command, route.operation
    ));
    lines
}

fn live_owner_status_human_lines(route: &LivePoolRoute<'_>) -> Vec<String> {
    if !is_status_route(route) {
        return Vec::new();
    }

    let mut lines = vec![format!(
        "path:       tidefsctl {} {}",
        route.command, route.operation
    )];
    if let Some(scope) = live_owner_status_scope(route) {
        lines.push(format!("scope:      {scope}"));
    }
    lines.push(format!(
        "source_classification: {}",
        super::classification::StatusSource::LiveOwner.label()
    ));
    lines
}

fn decode_live_owner_hex(value: &str) -> Result<Vec<u8>, LiveOwnerRequestError> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if !hex.len().is_multiple_of(2) {
        return Err(LiveOwnerRequestError::Owner {
            exit_code: 2,
            message: "decode live-owner byte response: odd-length hex".to_string(),
            detail: None,
        });
    }
    hex.as_bytes()
        .chunks(2)
        .map(|chunk| {
            let part = std::str::from_utf8(chunk).map_err(|err| LiveOwnerRequestError::Owner {
                exit_code: 2,
                message: format!("decode live-owner byte response: invalid UTF-8: {err}"),
                detail: None,
            })?;
            u8::from_str_radix(part, 16).map_err(|err| LiveOwnerRequestError::Owner {
                exit_code: 2,
                message: format!("decode live-owner byte response: invalid hex byte {part}: {err}"),
                detail: None,
            })
        })
        .collect()
}

fn print_live_owner_status_classification(route: &LivePoolRoute<'_>) {
    for line in live_owner_status_human_lines(route) {
        println!("{line}");
    }
}

fn live_owner_request(
    route: &LivePoolRoute<'_>,
) -> Result<LivePoolAdminRequest, LiveOwnerRequestError> {
    let command = LivePoolAdminCommand::from_parts(route.command, route.operation)
        .map_err(live_admin_error_to_request_error)?;
    let mut request = LivePoolAdminRequest::new(command, route.pool);
    request.output = if route.json {
        LivePoolAdminOutput::MachineJson
    } else {
        LivePoolAdminOutput::Human
    };
    if let Some(pool_uuid) = route.pool_uuid {
        request.pool_uuid = Some(hex_uuid(&pool_uuid));
    }
    request.args = route.args.clone();
    Ok(request)
}

fn live_admin_error_to_request_error(err: LivePoolAdminError) -> LiveOwnerRequestError {
    LiveOwnerRequestError::Owner {
        exit_code: err.exit_code,
        message: err.message,
        detail: serde_json::to_value(err.kind).ok(),
    }
}

fn find_live_owner_manifest_at(
    root: &Path,
    route: &LivePoolRoute<'_>,
) -> Result<serde_json::Value, LiveOwnerRequestError> {
    let mut cached_match: Option<serde_json::Value> = None;
    let mut exact_mismatch: Option<String> = None;

    if let Some(pool_uuid) = route.pool_uuid {
        let manifest_path = owner_manifest_path(root, &pool_uuid);
        if let Some(manifest) = read_manifest_if_exists(&manifest_path)? {
            if manifest_matches_route(&manifest, route) {
                if manifest_has_reachable_interface(&manifest) {
                    return Ok(manifest);
                }
                cached_match = Some(manifest);
            } else {
                exact_mismatch = Some(format!(
                    "live owner manifest {} does not match pool '{}' uuid {}",
                    manifest_path.display(),
                    route.pool,
                    hex_uuid(&pool_uuid)
                ));
            }
        }
    }

    let entries = match std::fs::read_dir(&root) {
        Ok(entries) => entries,
        Err(err) => {
            if cached_match.is_some() {
                return Err(cached_without_reachable_interface(route));
            }
            if let Some(message) = exact_mismatch {
                return Err(LiveOwnerRequestError::Unavailable(message));
            }
            return Err(LiveOwnerRequestError::Unavailable(format!(
                "read {}: {err}",
                root.display()
            )));
        }
    };
    for entry in entries {
        let entry = entry.map_err(|err| {
            LiveOwnerRequestError::Unavailable(format!("read {} entry: {err}", root.display()))
        })?;
        let path = entry.path().join("owner.json");
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if manifest_matches_route(&manifest, route) {
            if manifest_has_reachable_interface(&manifest) {
                return Ok(manifest);
            }
            if cached_match.is_none() {
                cached_match = Some(manifest);
            }
        }
    }
    if cached_match.is_some() {
        return Err(cached_without_reachable_interface(route));
    }
    if let Some(message) = exact_mismatch {
        return Err(LiveOwnerRequestError::Unavailable(message));
    }
    Err(LiveOwnerRequestError::Unavailable(format!(
        "no live owner manifest for pool '{pool}'",
        pool = route.pool
    )))
}

fn cached_without_reachable_interface(route: &LivePoolRoute<'_>) -> LiveOwnerRequestError {
    let mut message = format!(
        "cached imported-pool state exists for pool '{}', but no live owner interface is reachable",
        route.pool
    );
    if let Some(pool_uuid) = route.pool_uuid {
        message.push_str(&format!(" (uuid {})", hex_uuid(&pool_uuid)));
    }
    LiveOwnerRequestError::Unavailable(message)
}

fn manifest_matches_route(manifest: &serde_json::Value, route: &LivePoolRoute<'_>) -> bool {
    let name_matches = manifest
        .get("pool_name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|name| name == route.pool);
    if !name_matches {
        return false;
    }

    let Some(pool_uuid) = route.pool_uuid else {
        return true;
    };
    let expected = hex_uuid(&pool_uuid);
    manifest
        .get("pool_uuid")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|uuid| uuid.eq_ignore_ascii_case(&expected))
}

fn owner_interface_reachable_by_uuid_at(root: &Path, uuid: &[u8; 16]) -> bool {
    let manifest_path = owner_manifest_path(root, uuid);
    let Ok(Some(manifest)) = read_manifest_if_exists(&manifest_path) else {
        return false;
    };
    manifest_uuid_matches(&manifest, uuid) && manifest_has_reachable_interface(&manifest)
}

fn owner_interface_reachable_by_pool_uuid_at(root: &Path, pool: &str, uuid: &[u8; 16]) -> bool {
    let expected_uuid = hex_uuid(uuid);
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return false,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => continue,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        let name_matches = manifest
            .get("pool_name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == pool);
        let uuid_matches = manifest
            .get("pool_uuid")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|manifest_uuid| manifest_uuid.eq_ignore_ascii_case(&expected_uuid));
        if name_matches && uuid_matches && manifest_has_reachable_interface(&manifest) {
            return true;
        }
    }
    false
}

fn owner_interface_reachable_for_uuid_at(root: &Path, pool: &str, uuid: &[u8; 16]) -> bool {
    owner_interface_reachable_by_uuid_at(root, uuid)
        || owner_interface_reachable_by_pool_uuid_at(root, pool, uuid)
}

fn owner_record_cached_by_pool_at(root: &Path, pool: &str) -> bool {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return false,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => continue,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if manifest_pool_name(&manifest).is_some_and(|name| name == pool) {
            return true;
        }
    }
    false
}

fn owner_record_cached_for_uuid_at(root: &Path, pool: &str, uuid: &[u8; 16]) -> bool {
    match owner_manifest_path(root, uuid).try_exists() {
        Ok(true) => return true,
        Ok(false) => {}
        Err(_) => return true,
    }

    let expected_uuid = hex_uuid(uuid);
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return false,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => continue,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        let name_matches = manifest_pool_name(&manifest).is_some_and(|name| name == pool);
        let uuid_matches = manifest
            .get("pool_uuid")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|manifest_uuid| manifest_uuid.eq_ignore_ascii_case(&expected_uuid));
        if name_matches && uuid_matches {
            return true;
        }
    }
    false
}

fn owner_interface_reachable_by_pool_at(root: &Path, pool: &str) -> bool {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => return false,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => continue,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if manifest
            .get("pool_name")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|name| name == pool)
            && manifest_has_reachable_interface(&manifest)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
fn owner_interface_reachable_by_pool_backing_dir_at(
    root: &Path,
    pool: &str,
    backing_dir: &Path,
) -> Option<[u8; 16]> {
    owner_interface_reachable_by_backing_dir_at(root, backing_dir).and_then(|(owner_pool, uuid)| {
        if owner_pool == pool {
            Some(uuid)
        } else {
            None
        }
    })
}

#[cfg(test)]
fn cached_owner_by_pool_backing_dir_at(
    root: &Path,
    pool: &str,
    backing_dir: &Path,
) -> Option<[u8; 16]> {
    cached_owner_by_backing_dir_at(root, backing_dir).and_then(|(owner_pool, uuid)| {
        if owner_pool == pool {
            Some(uuid)
        } else {
            None
        }
    })
}

fn owner_interface_reachable_by_backing_dir_at(
    root: &Path,
    backing_dir: &Path,
) -> Option<(String, [u8; 16])> {
    owner_by_backing_dir_at(root, backing_dir, true)
}

fn cached_owner_by_backing_dir_at(root: &Path, backing_dir: &Path) -> Option<(String, [u8; 16])> {
    owner_by_backing_dir_at(root, backing_dir, false)
}

fn imported_owner_by_backing_dir_at(
    root: &Path,
    backing_dir: &Path,
) -> Option<ImportedBackingDirOwner> {
    if let Some((pool, pool_uuid)) = owner_interface_reachable_by_backing_dir_at(root, backing_dir)
    {
        return Some(ImportedBackingDirOwner {
            pool,
            pool_uuid,
            reachable: true,
        });
    }
    cached_owner_by_backing_dir_at(root, backing_dir).map(|(pool, pool_uuid)| {
        ImportedBackingDirOwner {
            pool,
            pool_uuid,
            reachable: false,
        }
    })
}

fn imported_backing_dir_decision_at(
    root: &Path,
    pool: &str,
    backing_dir: &Path,
) -> Option<ImportedBackingDirDecision> {
    imported_owner_by_backing_dir_at(root, backing_dir).map(|owner| {
        if owner.pool == pool {
            ImportedBackingDirDecision::Exact(owner)
        } else {
            ImportedBackingDirDecision::Foreign(owner)
        }
    })
}

fn owner_by_backing_dir_at(
    root: &Path,
    backing_dir: &Path,
    require_reachable_socket: bool,
) -> Option<(String, [u8; 16])> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return None,
        Err(_) => return None,
    };
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path().join("owner.json");
        match path.try_exists() {
            Ok(true) => {}
            Ok(false) => continue,
            Err(_) => continue,
        }
        let Ok(manifest) = read_manifest(&path) else {
            continue;
        };
        if !manifest_backing_dir_matches(&manifest, backing_dir) {
            continue;
        }
        let Some(pool_name) = manifest_pool_name(&manifest) else {
            continue;
        };
        let Some(pool_uuid) = manifest_pool_uuid_bytes(&manifest) else {
            continue;
        };
        if require_reachable_socket && !manifest_has_reachable_interface(&manifest) {
            continue;
        }
        return Some((pool_name.to_string(), pool_uuid));
    }
    None
}

fn owner_manifest_path(root: &Path, uuid: &[u8; 16]) -> PathBuf {
    root.join(hex_uuid(uuid)).join("owner.json")
}

fn read_manifest_if_exists(
    path: &Path,
) -> Result<Option<serde_json::Value>, LiveOwnerRequestError> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(LiveOwnerRequestError::Unavailable(format!(
                "read live owner manifest {}: {err}",
                path.display()
            )))
        }
    };
    serde_json::from_str(&text).map(Some).map_err(|err| {
        LiveOwnerRequestError::Unavailable(format!("decode {}: {err}", path.display()))
    })
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

fn manifest_socket_endpoint(
    manifest: &serde_json::Value,
    route: &LivePoolRoute<'_>,
) -> Result<PathBuf, LiveOwnerRequestError> {
    match manifest_owner_kind(manifest) {
        Some("kernel") => {
            let endpoint = manifest_kernel_uapi_path(manifest)
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "undeclared kernel UAPI endpoint".to_string());
            Err(LiveOwnerRequestError::Unavailable(format!(
                "kernel live owner for imported pool '{}' is declared at {endpoint}, but tidefsctl has no kernel UAPI admin client wired yet",
                route.pool
            )))
        }
        Some("fuse" | "ublk" | "daemon" | "userspace") | None => manifest_socket_path(manifest),
        Some(other) => Err(LiveOwnerRequestError::Unavailable(format!(
            "unsupported live owner kind '{other}' for imported pool '{}'",
            route.pool
        ))),
    }
}

fn manifest_has_reachable_interface(manifest: &serde_json::Value) -> bool {
    if matches!(manifest_owner_kind(manifest), Some("kernel")) {
        return manifest_kernel_uapi_path(manifest).is_some_and(|path| path.exists());
    }
    let Ok(socket_path) = manifest_socket_path(manifest) else {
        return false;
    };
    UnixStream::connect(socket_path).is_ok()
}

fn manifest_owner_kind(manifest: &serde_json::Value) -> Option<&str> {
    manifest
        .get("owner_kind")
        .and_then(serde_json::Value::as_str)
}

fn manifest_kernel_uapi_path(manifest: &serde_json::Value) -> Option<PathBuf> {
    manifest
        .get("kernel_uapi_path")
        .or_else(|| manifest.get("uapi_path"))
        .and_then(serde_json::Value::as_str)
        .map(PathBuf::from)
}

fn manifest_uuid_matches(manifest: &serde_json::Value, uuid: &[u8; 16]) -> bool {
    let expected = hex_uuid(uuid);
    manifest
        .get("pool_uuid")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|manifest_uuid| manifest_uuid.eq_ignore_ascii_case(&expected))
}

fn manifest_pool_uuid_bytes(manifest: &serde_json::Value) -> Option<[u8; 16]> {
    manifest
        .get("pool_uuid")
        .and_then(serde_json::Value::as_str)
        .and_then(parse_hex_uuid)
}

fn manifest_pool_name(manifest: &serde_json::Value) -> Option<&str> {
    manifest
        .get("pool_name")
        .and_then(serde_json::Value::as_str)
}

fn manifest_backing_dir_matches(manifest: &serde_json::Value, backing_dir: &Path) -> bool {
    let Some(manifest_backing_dir) = manifest
        .get("backing_dir")
        .and_then(serde_json::Value::as_str)
    else {
        return false;
    };
    paths_refer_to_same_location(Path::new(manifest_backing_dir), backing_dir)
}

fn parse_hex_uuid(value: &str) -> Option<[u8; 16]> {
    if value.len() != 32 {
        return None;
    }
    let mut out = [0_u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let start = idx * 2;
        let end = start + 2;
        *byte = u8::from_str_radix(&value[start..end], 16).ok()?;
    }
    Some(out)
}

fn paths_refer_to_same_location(left: &Path, right: &Path) -> bool {
    if let (Ok(left), Ok(right)) = (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        return left == right;
    }
    left == right
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
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::thread;

    use tidefs_device_removal::admission::{
        DeviceRemovalAdmissionEvidence, DEVICE_REMOVAL_AUTHORITY_FIELD,
        DEVICE_REMOVAL_AUTHORITY_KIND,
    };
    use tidefs_device_removal::{EvacuationCompletionGeneration, EvacuationReceipt};

    fn write_owner_manifest(root: &Path, socket_path: &Path) {
        let uuid = [0x42; 16];
        let manifest_path = owner_manifest_path(root, &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();
    }

    fn test_receipt(device_guid: [u8; 16], topology_generation: u64) -> EvacuationReceipt {
        EvacuationReceipt::new(
            EvacuationCompletionGeneration {
                target_device_guid: device_guid,
                target_topology_generation: topology_generation,
                evacuation_set_digest: [0x55; 32],
                removal_chain_digest: [0x66; 32],
            },
            vec![],
            9,
        )
    }

    fn spawn_owner_response(
        listener: UnixListener,
        response: LivePoolAdminResponse,
    ) -> thread::JoinHandle<LivePoolAdminRequest> {
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                if line.trim().is_empty() {
                    continue;
                }
                let request: LivePoolAdminRequest = serde_json::from_str(&line).unwrap();
                stream
                    .write_all(serde_json::to_string(&response).unwrap().as_bytes())
                    .unwrap();
                stream.write_all(b"\n").unwrap();
                return request;
            }
            panic!("live-owner test did not receive request");
        })
    }

    fn spawn_owner_raw_response(
        listener: UnixListener,
        response: &'static [u8],
    ) -> thread::JoinHandle<LivePoolAdminRequest> {
        thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = String::new();
                BufReader::new(stream.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                if line.trim().is_empty() {
                    continue;
                }
                let request: LivePoolAdminRequest = serde_json::from_str(&line).unwrap();
                stream.write_all(response).unwrap();
                return request;
            }
            panic!("live-owner test did not receive request");
        })
    }

    fn device_remove_route() -> LivePoolRoute<'static> {
        LivePoolRoute {
            command: "device",
            operation: "remove",
            pool: "tank",
            pool_uuid: None,
            json: false,
            args: live_admin_args([
                ("device_path", LivePoolAdminArg::String("/dev/disk2".into())),
                (
                    "required_authority",
                    LivePoolAdminArg::String(DEVICE_REMOVAL_AUTHORITY_KIND.into()),
                ),
            ]),
        }
    }

    #[test]
    fn owner_interface_requires_decodable_manifest_and_reachable_socket() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(&manifest_path, b"not json").unwrap();

        assert!(!owner_interface_reachable_by_uuid_at(dir.path(), &uuid));

        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        assert!(!owner_interface_reachable_by_uuid_at(dir.path(), &uuid));
    }

    #[test]
    fn device_remove_live_owner_response_requires_committed_receipt_authority() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_response(listener, LivePoolAdminResponse::ok_text("removed"));
        let route = device_remove_route();

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(
            request.args.0.get("required_authority"),
            Some(&LivePoolAdminArg::String(
                DEVICE_REMOVAL_AUTHORITY_KIND.to_string()
            ))
        );
        match err {
            LiveOwnerRequestError::Owner { message, .. } => {
                assert!(message.contains("committed evacuation receipt authority"));
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("missing authority should be an owner refusal, got {message}");
            }
        }
    }

    #[test]
    fn device_remove_live_owner_accepts_receipt_shaped_authority() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let receipt = test_receipt([0x42; 16], 11);
        let authority =
            DeviceRemovalAdmissionEvidence::committed("tank", "/dev/disk2", 11, receipt);
        let mut response = serde_json::json!({
            "ok": true,
            "text": "removed",
        });
        response[DEVICE_REMOVAL_AUTHORITY_FIELD] = serde_json::to_value(authority).unwrap();
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::ok_machine_json(serde_json::to_string(&response).unwrap()),
        );
        let route = device_remove_route();

        send_live_owner_request_at(dir.path(), &route).unwrap();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::DeviceRemove);
    }

    #[test]
    fn unsupported_live_owner_response_version_precedes_future_shape() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_raw_response(
            listener,
            b"{\"version\":42,\"exit_code\":\"future\",\"body\":{\"kind\":\"future\"},\"unexpected\":true}\n",
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(
                    message,
                    "unsupported live-owner response version 42; expected 1"
                );
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("unsupported_version")
                );
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("version"))
                        .and_then(serde_json::Value::as_u64),
                    Some(42)
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed version refusal, got {message}");
            }
        }
    }

    #[test]
    fn nonzero_success_live_owner_response_is_typed_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let mut response = LivePoolAdminResponse::ok_text("ok");
        response.exit_code = 1;
        let handle = spawn_owner_response(listener, response);
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(
                    message,
                    "live-owner response exit code is inconsistent with response body"
                );
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn zero_exit_error_live_owner_response_is_typed_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let mut response = LivePoolAdminResponse::error(1, "owner failed");
        response.exit_code = 0;
        let handle = spawn_owner_response(listener, response);
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(
                    message,
                    "live-owner response exit code is inconsistent with response body"
                );
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn live_owner_byte_response_rejects_declared_length_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let response = LivePoolAdminResponse::ok_bytes_hex("00", 2);
        let handle = spawn_owner_response(listener, response);
        let route = LivePoolRoute {
            command: "snapshot",
            operation: "send",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::SnapshotSend);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(
                    message,
                    "live-owner byte response length mismatch: declared 2, decoded 1"
                );
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn empty_live_owner_response_preserves_typed_malformed_detail() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_raw_response(listener, b"\n");
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert_eq!(message, "empty live-owner response");
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn undecodable_live_owner_response_preserves_typed_malformed_detail() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_raw_response(listener, b"not-json\n");
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert!(message.starts_with("decode live-owner response:"));
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn unknown_live_owner_response_field_preserves_typed_malformed_detail() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_raw_response(
            listener,
            b"{\"version\":1,\"exit_code\":0,\"body\":{\"kind\":\"text\",\"value\":\"ok\"},\"unexpected\":true}\n",
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert!(message.starts_with("decode live-owner response:"));
                assert!(message.contains("unknown field `unexpected`"));
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("kind"))
                        .and_then(serde_json::Value::as_str),
                    Some("malformed")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should return typed malformed refusal, got {message}");
            }
        }
    }

    #[test]
    fn invalid_live_owner_error_machine_json_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::error_machine_json(1, "owner failed", "not-json"),
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 2);
                assert!(message.starts_with("decode live-owner machine JSON:"));
                assert!(detail.is_none());
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should fail closed on malformed detail, got {message}");
            }
        }
    }

    #[test]
    fn pool_destroy_live_owner_request_preserves_destroy_boundary_args() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::error_machine_json(
                1,
                "destroy refused",
                serde_json::json!({
                    "code": "live-owner-pool-destroy-refused",
                    "force_requested": true,
                    "zero_superblock_requested": true
                })
                .to_string(),
            ),
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "destroy",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: live_admin_args([
                ("force", LivePoolAdminArg::Bool(true)),
                ("zero_superblock", LivePoolAdminArg::Bool(true)),
            ]),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolDestroy);
        assert_eq!(
            request.pool_uuid.as_deref(),
            Some("42424242424242424242424242424242")
        );
        assert_eq!(
            request.args.0.get("force"),
            Some(&LivePoolAdminArg::Bool(true))
        );
        assert_eq!(
            request.args.0.get("zero_superblock"),
            Some(&LivePoolAdminArg::Bool(true))
        );
        match err {
            LiveOwnerRequestError::Owner {
                message, detail, ..
            } => {
                assert_eq!(message, "destroy refused");
                assert_eq!(
                    detail
                        .as_ref()
                        .and_then(|value| value.get("code"))
                        .and_then(serde_json::Value::as_str),
                    Some("live-owner-pool-destroy-refused")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("reachable owner should receive destroy request, got {message}");
            }
        }
    }

    #[test]
    fn block_live_owner_routes_build_typed_requests() {
        for (operation, expected_command, expected_arg) in [
            (
                "attach",
                LivePoolAdminCommand::BlockAttach,
                ("queue_depth", LivePoolAdminArg::U64(64)),
            ),
            (
                "send",
                LivePoolAdminCommand::BlockSend,
                (
                    "target_addr",
                    LivePoolAdminArg::String("127.0.0.1:9000".to_string()),
                ),
            ),
            (
                "receive",
                LivePoolAdminCommand::BlockReceive,
                (
                    "source_addr",
                    LivePoolAdminArg::String("127.0.0.1:9001".to_string()),
                ),
            ),
        ] {
            let route = LivePoolRoute {
                command: "block",
                operation,
                pool: "tank",
                pool_uuid: Some([0x42; 16]),
                json: true,
                args: live_admin_args([expected_arg.clone()]),
            };

            let request = live_owner_request(&route).expect("build block live-owner request");

            assert_eq!(request.command, expected_command);
            assert_eq!(request.output, LivePoolAdminOutput::MachineJson);
            assert_eq!(
                request.pool_uuid.as_deref(),
                Some("42424242424242424242424242424242")
            );
            assert_eq!(request.args.0.get(expected_arg.0), Some(&expected_arg.1));
        }
    }

    #[test]
    fn send_live_owner_request_rejects_unsupported_command_before_manifest_lookup() {
        let dir = tempfile::tempdir().unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "unknown",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();

        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail,
            } => {
                assert_eq!(exit_code, 1);
                assert_eq!(
                    message,
                    "unsupported live-owner command tidefsctl pool unknown"
                );
                let detail = detail.expect("typed unsupported-command detail");
                assert_eq!(
                    detail.get("kind").and_then(serde_json::Value::as_str),
                    Some("unsupported_command")
                );
                assert_eq!(
                    detail.get("command").and_then(serde_json::Value::as_str),
                    Some("pool")
                );
                assert_eq!(
                    detail.get("operation").and_then(serde_json::Value::as_str),
                    Some("unknown")
                );
            }
            LiveOwnerRequestError::Unavailable(message) => {
                panic!("unsupported route should fail before socket lookup, got {message}");
            }
        }
    }

    #[test]
    fn device_remove_cached_owner_refusal_names_receipt_authority() {
        let json = cached_without_owner_json("device", "remove", "tank", None);

        assert_eq!(
            json.get("source:status")
                .and_then(serde_json::Value::as_str),
            Some(super::super::classification::StatusSource::CachedLocalMetadata.label())
        );
        assert_eq!(
            json.get("required_authority")
                .and_then(serde_json::Value::as_str),
            Some(DEVICE_REMOVAL_AUTHORITY_KIND)
        );
        assert!(json
            .get("authority_error")
            .and_then(serde_json::Value::as_str)
            .unwrap()
            .contains("committed evacuation receipt authority"));

        let lines = cached_without_owner_lines("device", "remove", "tank", None);
        assert!(lines
            .iter()
            .any(|line| line.contains("[source:cached-local-metadata]")));
        assert!(lines
            .iter()
            .any(|line| line.contains("committed evacuation receipt authority")));
        assert!(lines
            .iter()
            .any(|line| line.contains("cached imported-pool state is not removal authority")));
    }

    #[test]
    fn device_remove_unavailable_owner_refusal_names_target_device_authority() {
        let line = device_removal_authority_line("device", "remove", Some("/dev/disk2"))
            .expect("device removal should require receipt authority");

        assert!(line.contains("committed evacuation receipt authority"));
        assert!(line.contains("/dev/disk2"));
        assert!(device_removal_authority_line("device", "status", Some("/dev/disk2")).is_none());
    }

    #[test]
    fn status_json_refusal_names_unavailable_owner_and_unsupported_local_mode() {
        let json = no_live_status_refusal_json("device", "status", "tank");

        assert_eq!(json["ok"], false);
        assert_eq!(json["command"], "device");
        assert_eq!(json["operation"], "status");
        assert_eq!(json["pool_name"], "tank");
        assert_eq!(
            json.get("source_classification")
                .and_then(serde_json::Value::as_str),
            Some(super::super::classification::StatusSource::UnavailableLiveOwner.label())
        );
        assert_eq!(
            json.get("local_mode_classification")
                .and_then(serde_json::Value::as_str),
            Some(super::super::classification::StatusSource::UnsupportedLocalMode.label())
        );
        assert!(json["error"].as_str().is_some_and(|error| {
            error.contains("no live status evidence obtained")
                && error.contains("cached local metadata is non-authoritative")
        }));
        assert!(json["recovery"]
            .as_str()
            .is_some_and(|recovery| recovery.contains("start or repair")));

        let output = no_live_status_refusal_lines("device", "status", "tank").join("\n");
        assert!(output.contains("no live status evidence obtained"));
        assert!(output.contains("[source:unavailable-live-owner]"));
        assert!(output.contains("[source:unsupported-local-mode]"));
        assert!(output.contains("cached local metadata"));
        assert!(output.contains("non-authoritative"));
    }

    #[test]
    fn live_pool_status_reaches_owner_and_classifies_typed_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let owner_error = LivePoolAdminError::unsupported_command("pool", "status");
        let machine_json = serde_json::to_string(&owner_error.kind).unwrap();
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::error_machine_json(
                owner_error.exit_code,
                owner_error.message,
                machine_json,
            ),
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        assert_eq!(request.output, LivePoolAdminOutput::MachineJson);
        let (message, detail) = match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail: Some(detail),
            } => {
                assert_eq!(exit_code, 1);
                assert_eq!(detail["kind"], "unsupported_command");
                assert_eq!(detail["command"], "pool");
                assert_eq!(detail["operation"], "status");
                (message, detail)
            }
            other => panic!("expected typed live-owner refusal, got {other:?}"),
        };

        let mut value = live_owner_error_detail_json(&route, &message, &detail);

        annotate_live_owner_status_refusal_json(&route, Some(&detail), &mut value);

        assert_eq!(value["source_classification"], "source:live-owner");
        assert_eq!(value["owner_response"], "refused");
        assert_eq!(value["scope"], "local-pool");
        assert_eq!(value["status_facts_accepted"], false);

        let output = live_owner_status_refusal_human_lines(&route, Some(&detail)).join("\n");
        assert!(output.contains("path:       tidefsctl pool status"));
        assert!(output.contains("scope:      local-pool"));
        assert!(output.contains("response:   refused"));
        assert!(output.contains("no pool status facts were accepted"));
        assert!(!output.trim_start().starts_with('{'));
    }

    #[test]
    fn pool_status_refusal_requires_exact_owner_detail() {
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        for detail in [
            None,
            Some(serde_json::json!("malformed")),
            Some(serde_json::json!({"kind": "malformed"})),
            Some(serde_json::json!({
                "kind": "unsupported_command",
                "command": "device",
                "operation": "status",
            })),
            Some(serde_json::json!({
                "kind": "unsupported_command",
                "command": "pool",
                "operation": "remove",
            })),
        ] {
            let mut value = serde_json::json!({"ok": false});

            annotate_live_owner_status_refusal_json(&route, detail.as_ref(), &mut value);

            assert!(value.get("owner_response").is_none());
            assert!(value.get("status_facts_accepted").is_none());
            assert!(live_owner_status_refusal_human_lines(&route, detail.as_ref()).is_empty());
        }
    }

    #[test]
    fn device_status_refusal_remains_generic() {
        let route = LivePoolRoute {
            command: "device",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        for (name, detail) in [
            ("missing", None),
            ("malformed", Some(serde_json::json!({"kind": "malformed"}))),
            (
                "unsupported-version",
                Some(serde_json::json!({
                    "kind": "unsupported_version",
                    "version": 42,
                })),
            ),
            (
                "exact-device-status",
                Some(serde_json::json!({
                    "kind": "unsupported_command",
                    "command": "device",
                    "operation": "status",
                })),
            ),
            (
                "wrong-command",
                Some(serde_json::json!({
                    "kind": "unsupported_command",
                    "command": "cluster",
                    "operation": "status",
                })),
            ),
            (
                "wrong-operation",
                Some(serde_json::json!({
                    "kind": "unsupported_command",
                    "command": "device",
                    "operation": "remove",
                })),
            ),
        ] {
            let mut value = serde_json::json!({"ok": false});

            annotate_live_owner_status_refusal_json(&route, detail.as_ref(), &mut value);

            assert!(
                value.get("owner_response").is_none(),
                "{name} owner error must not be classified as a status refusal"
            );
            assert!(
                value.get("status_facts_accepted").is_none(),
                "{name} owner error must not gain status-refusal fields"
            );
            assert!(
                live_owner_status_refusal_human_lines(&route, detail.as_ref()).is_empty(),
                "{name} owner error must not render exact-refusal lines"
            );
        }
    }

    #[test]
    fn device_status_reaches_owner_and_preserves_typed_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let owner_error = LivePoolAdminError::unsupported_command("device", "status");
        let machine_json = serde_json::to_string(&owner_error.kind).unwrap();
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::error_machine_json(
                owner_error.exit_code,
                owner_error.message,
                machine_json,
            ),
        );
        let route = LivePoolRoute {
            command: "device",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let err = send_live_owner_request_at(dir.path(), &route).unwrap_err();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::DeviceStatus);
        assert_eq!(request.output, LivePoolAdminOutput::MachineJson);
        match err {
            LiveOwnerRequestError::Owner {
                exit_code,
                message,
                detail: Some(detail),
            } => {
                assert_eq!(exit_code, 1);
                assert_eq!(
                    message,
                    "unsupported live-owner command tidefsctl device status"
                );
                assert_eq!(detail["kind"], "unsupported_command");
                assert_eq!(detail["command"], "device");
                assert_eq!(detail["operation"], "status");
            }
            other => panic!("expected typed live-owner refusal, got {other:?}"),
        }
    }

    #[test]
    fn live_owner_status_json_is_annotated_when_owner_omits_source() {
        let route = LivePoolRoute {
            command: "device",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: true,
            args: LivePoolAdminArgs::default(),
        };
        let mut value = serde_json::json!({"ok": true, "devices": []});

        annotate_live_owner_status_json(&route, &mut value);

        assert_eq!(
            value
                .get("source_classification")
                .and_then(serde_json::Value::as_str),
            Some(super::super::classification::StatusSource::LiveOwner.label())
        );
        assert_eq!(value["devices"], serde_json::json!([]));
        assert!(value.get("scope").is_none());
    }

    #[test]
    fn live_pool_status_json_carries_local_scope() {
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: true,
            args: LivePoolAdminArgs::default(),
        };
        let mut value = serde_json::json!({
            "pool_name": "tank",
            "state": "Active",
            "statfs": {"total_blocks": 1024, "free_blocks": 768},
        });

        annotate_live_owner_status_json(&route, &mut value);

        assert_eq!(value["source_classification"], "source:live-owner");
        assert_eq!(value["scope"], "local-pool");
        assert_eq!(value["state"], "Active");
        assert_eq!(value["statfs"]["free_blocks"], 768);
    }

    #[test]
    fn live_pool_status_reaches_owner_through_typed_socket_path() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        write_owner_manifest(dir.path(), &socket_path);
        let handle = spawn_owner_response(
            listener,
            LivePoolAdminResponse::ok_machine_json(
                serde_json::json!({
                    "pool_name": "tank",
                    "pool_uuid": "42424242424242424242424242424242",
                    "state": "Active",
                    "statfs": {"total_blocks": 1024, "free_blocks": 768},
                })
                .to_string(),
            ),
        );
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        send_live_owner_request_at(dir.path(), &route).unwrap();
        let request = handle.join().unwrap();

        assert_eq!(request.command, LivePoolAdminCommand::PoolStatus);
        assert_eq!(request.output, LivePoolAdminOutput::MachineJson);
        assert_eq!(
            request.pool_uuid.as_deref(),
            Some("42424242424242424242424242424242")
        );
    }

    #[test]
    fn live_owner_status_text_json_carries_concise_source() {
        let route = LivePoolRoute {
            command: "cluster",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: true,
            args: LivePoolAdminArgs::default(),
        };

        let value = live_owner_status_text_json(&route, "healthy");

        assert_eq!(value["text"], "healthy");
        assert_eq!(value["command"], "cluster");
        assert_eq!(value["operation"], "status");
        assert_eq!(value["pool_name"], "tank");
        assert_eq!(value["source_classification"], "source:live-owner");
        assert!(value.get("scope").is_none());
    }

    #[test]
    fn live_owner_machine_json_human_lines_preserve_status_source() {
        let route = LivePoolRoute {
            command: "device",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: false,
            args: LivePoolAdminArgs::default(),
        };
        let value = serde_json::json!({
            "ok": true,
            "text": "live status\n\nready",
        });

        let lines = live_owner_machine_json_human_lines(&route, &value);
        let output = lines.join("\n");
        let expected_source = format!(
            "source_classification: {}",
            super::super::classification::StatusSource::LiveOwner.label()
        );

        assert!(output.contains("path:       tidefsctl device status"));
        assert!(lines.iter().any(|line| line == &expected_source));
        assert!(lines.iter().any(|line| line == "live status"));
        assert!(lines.iter().any(|line| line == "ready"));
        assert!(!output.trim_start().starts_with('{'));
    }

    #[test]
    fn live_pool_status_is_operator_readable_by_default() {
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: false,
            args: LivePoolAdminArgs::default(),
        };
        let value = serde_json::json!({
            "text": "pool: tank\nstate: Active",
        });

        let lines = live_owner_machine_json_human_lines(&route, &value);
        let output = lines.join("\n");

        assert!(output.contains("path:       tidefsctl pool status"));
        assert!(output.contains("scope:      local-pool"));
        assert!(output.contains("source_classification: source:live-owner"));
        assert!(lines.iter().any(|line| line == "pool: tank"));
        assert!(lines.iter().any(|line| line == "state: Active"));
        assert!(!output.trim_start().starts_with('{'));
    }

    #[test]
    fn live_owner_machine_json_human_lines_avoid_raw_json_fallback() {
        let route = LivePoolRoute {
            command: "dataset",
            operation: "list",
            pool: "tank",
            pool_uuid: None,
            json: false,
            args: LivePoolAdminArgs::default(),
        };
        let value = serde_json::json!({
            "ok": true,
            "devices": [],
        });

        let lines = live_owner_machine_json_human_lines(&route, &value);
        let output = lines.join("\n");

        assert!(!output.contains("devices"));
        assert!(!output.contains("[]"));
        assert!(output.contains("--json"));
    }

    #[test]
    fn cached_owner_record_for_uuid_does_not_require_reachable_socket() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        assert!(owner_record_cached_for_uuid_at(dir.path(), "tank", &uuid));
        assert!(!owner_interface_reachable_for_uuid_at(
            dir.path(),
            "tank",
            &uuid
        ));
    }

    #[test]
    fn exact_cached_owner_record_for_uuid_is_imported_state_even_when_stale() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "old-name",
                "pool_uuid": "24242424242424242424242424242424",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        assert!(owner_record_cached_for_uuid_at(dir.path(), "tank", &uuid));
        assert!(!owner_interface_reachable_for_uuid_at(
            dir.path(),
            "tank",
            &uuid
        ));
    }

    #[test]
    fn owner_interface_reachable_by_pool_when_manifest_names_pool() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x24; 16];
        let socket_path = dir.path().join("owner.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "24242424242424242424242424242424",
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();

        assert!(owner_interface_reachable_by_pool_at(dir.path(), "tank"));
        assert!(!owner_interface_reachable_by_pool_at(dir.path(), "other"));
        assert!(owner_interface_reachable_by_pool_uuid_at(
            dir.path(),
            "tank",
            &[0x24; 16]
        ));
        assert!(!owner_interface_reachable_by_pool_uuid_at(
            dir.path(),
            "tank",
            &[0x42; 16]
        ));
    }

    #[test]
    fn owner_interface_reachable_for_uuid_uses_uuid_not_pool_name_only() {
        let dir = tempfile::tempdir().unwrap();
        let matching_uuid = [0x42; 16];
        let other_uuid = [0x24; 16];
        let socket_path = dir.path().join("owner.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let manifest_path = dir.path().join("registry-entry").join("owner.json");
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();

        assert!(owner_interface_reachable_for_uuid_at(
            dir.path(),
            "tank",
            &matching_uuid
        ));
        assert!(!owner_interface_reachable_for_uuid_at(
            dir.path(),
            "tank",
            &other_uuid
        ));
    }

    #[test]
    fn owner_interface_absent_when_runtime_root_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing");

        assert!(!owner_interface_reachable_by_pool_at(&missing, "tank"));
        assert!(!owner_interface_reachable_by_uuid_at(&missing, &[0x11; 16]));
        assert_eq!(
            owner_interface_reachable_by_pool_backing_dir_at(
                &missing,
                "tank",
                dir.path().join("backing").as_path()
            ),
            None
        );
    }

    #[test]
    fn owner_interface_reachable_by_pool_backing_dir_requires_exact_storage_owner() {
        let dir = tempfile::tempdir().unwrap();
        let backing_dir = dir.path().join("backing");
        let other_backing_dir = dir.path().join("other-backing");
        std::fs::create_dir_all(&backing_dir).unwrap();
        std::fs::create_dir_all(&other_backing_dir).unwrap();
        let uuid = [0x55; 16];
        let socket_path = dir.path().join("owner.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "55555555555555555555555555555555",
                "backing_dir": backing_dir,
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            owner_interface_reachable_by_pool_backing_dir_at(dir.path(), "tank", &backing_dir),
            Some(uuid)
        );
        assert_eq!(
            owner_interface_reachable_by_backing_dir_at(dir.path(), &backing_dir),
            Some(("tank".to_string(), uuid))
        );
        assert_eq!(
            owner_interface_reachable_by_pool_backing_dir_at(
                dir.path(),
                "tank",
                &other_backing_dir
            ),
            None
        );
        assert_eq!(
            owner_interface_reachable_by_pool_backing_dir_at(dir.path(), "other", &backing_dir),
            None
        );
    }

    #[test]
    fn cached_owner_backing_dir_match_does_not_require_reachable_socket() {
        let dir = tempfile::tempdir().unwrap();
        let backing_dir = dir.path().join("backing");
        std::fs::create_dir_all(&backing_dir).unwrap();
        let uuid = [0x55; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "55555555555555555555555555555555",
                "backing_dir": backing_dir,
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        assert_eq!(
            cached_owner_by_pool_backing_dir_at(dir.path(), "tank", &backing_dir),
            Some(uuid)
        );
        assert_eq!(
            owner_interface_reachable_by_pool_backing_dir_at(dir.path(), "tank", &backing_dir),
            None
        );
    }

    #[test]
    fn imported_backing_dir_owner_reports_cached_owner_record() {
        let dir = tempfile::tempdir().unwrap();
        let backing_dir = dir.path().join("backing");
        std::fs::create_dir_all(&backing_dir).unwrap();
        let uuid = [0x55; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "55555555555555555555555555555555",
                "backing_dir": backing_dir,
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        let owner = imported_owner_by_backing_dir_at(dir.path(), &backing_dir).unwrap();

        assert_eq!(owner.pool, "tank");
        assert_eq!(owner.pool_uuid, uuid);
        assert!(!owner.reachable);
    }

    #[test]
    fn pool_specific_backing_dir_decision_refuses_foreign_imported_state() {
        let dir = tempfile::tempdir().unwrap();
        let backing_dir = dir.path().join("backing");
        std::fs::create_dir_all(&backing_dir).unwrap();
        let uuid = [0x65; 16];
        let manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "owner-pool",
                "pool_uuid": "65656565656565656565656565656565",
                "backing_dir": backing_dir,
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        let decision =
            imported_backing_dir_decision_at(dir.path(), "requested-pool", &backing_dir).unwrap();

        match decision {
            ImportedBackingDirDecision::Foreign(owner) => {
                assert_eq!(owner.pool, "owner-pool");
                assert_eq!(owner.pool_uuid, uuid);
                assert!(!owner.reachable);
            }
            ImportedBackingDirDecision::Exact(owner) => {
                panic!("foreign imported state was treated as exact: {owner:?}")
            }
        }
    }

    #[test]
    fn owner_lookup_with_uuid_falls_back_to_reachable_pool_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("owner.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let manifest_path = dir.path().join("registry-entry").join("owner.json");
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let manifest = find_live_owner_manifest_at(dir.path(), &route).unwrap();

        assert_eq!(
            manifest
                .get("pool_name")
                .and_then(serde_json::Value::as_str),
            Some("tank")
        );
    }

    #[test]
    fn owner_lookup_refuses_cached_manifest_without_reachable_interface() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("registry-entry").join("owner.json");
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let err = find_live_owner_manifest_at(dir.path(), &route).unwrap_err();

        match err {
            LiveOwnerRequestError::Unavailable(message) => {
                assert!(message.contains("cached imported-pool state exists"));
                assert!(message.contains("no live owner interface"));
            }
            LiveOwnerRequestError::Owner { .. } => panic!("cached state is not owner transport"),
        }
    }

    #[test]
    fn owner_lookup_prefers_reachable_uuid_owner_over_stale_cache() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let stale_manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(stale_manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &stale_manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        let socket_path = dir.path().join("reachable-owner.sock");
        let _listener = UnixListener::bind(&socket_path).unwrap();
        let reachable_manifest_path = dir.path().join("registry-entry").join("owner.json");
        std::fs::create_dir_all(reachable_manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &reachable_manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": socket_path,
            })
            .to_string(),
        )
        .unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some(uuid),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let manifest = find_live_owner_manifest_at(dir.path(), &route).unwrap();
        let expected_socket = socket_path.display().to_string();

        assert_eq!(
            manifest
                .get("socket_path")
                .and_then(serde_json::Value::as_str),
            Some(expected_socket.as_str())
        );
    }

    #[test]
    fn owner_lookup_prefers_reachable_kernel_owner_over_stale_cache() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = [0x42; 16];
        let stale_manifest_path = owner_manifest_path(dir.path(), &uuid);
        std::fs::create_dir_all(stale_manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &stale_manifest_path,
            serde_json::json!({
                "owner_kind": "fuse",
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "socket_path": dir.path().join("missing-owner.sock"),
            })
            .to_string(),
        )
        .unwrap();

        let kernel_uapi_path = dir.path().join("kernel-uapi");
        std::fs::write(&kernel_uapi_path, b"placeholder").unwrap();
        let reachable_manifest_path = dir.path().join("kernel-entry").join("owner.json");
        std::fs::create_dir_all(reachable_manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &reachable_manifest_path,
            serde_json::json!({
                "owner_kind": "kernel",
                "pool_name": "tank",
                "pool_uuid": "42424242424242424242424242424242",
                "kernel_uapi_path": kernel_uapi_path,
            })
            .to_string(),
        )
        .unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some(uuid),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let manifest = find_live_owner_manifest_at(dir.path(), &route).unwrap();

        assert_eq!(
            manifest
                .get("owner_kind")
                .and_then(serde_json::Value::as_str),
            Some("kernel")
        );
    }

    #[test]
    fn kernel_owner_manifest_refuses_socket_transport() {
        let dir = tempfile::tempdir().unwrap();
        let kernel_uapi_path = dir.path().join("kernel-uapi");
        std::fs::write(&kernel_uapi_path, b"placeholder").unwrap();
        let manifest = serde_json::json!({
            "owner_kind": "kernel",
            "pool_name": "tank",
            "pool_uuid": "42424242424242424242424242424242",
            "kernel_uapi_path": kernel_uapi_path,
        });
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let err = manifest_socket_endpoint(&manifest, &route).unwrap_err();

        match err {
            LiveOwnerRequestError::Unavailable(message) => {
                assert!(message.contains("kernel live owner"));
                assert!(message.contains("no kernel UAPI admin client"));
            }
            LiveOwnerRequestError::Owner { .. } => {
                panic!("kernel owner should not use socket transport")
            }
        }
    }

    #[test]
    fn owner_lookup_with_uuid_rejects_same_name_mismatched_uuid() {
        let dir = tempfile::tempdir().unwrap();
        let manifest_path = dir.path().join("registry-entry").join("owner.json");
        std::fs::create_dir_all(manifest_path.parent().unwrap()).unwrap();
        std::fs::write(
            &manifest_path,
            serde_json::json!({
                "pool_name": "tank",
                "pool_uuid": "24242424242424242424242424242424",
                "socket_path": "/run/tidefs/pools/tank/owner.sock",
            })
            .to_string(),
        )
        .unwrap();
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: Some([0x42; 16]),
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let err = find_live_owner_manifest_at(dir.path(), &route).unwrap_err();

        assert!(matches!(err, LiveOwnerRequestError::Unavailable(_)));
    }

    #[test]
    fn live_owner_request_carries_pool_uuid_when_known() {
        let route = LivePoolRoute {
            command: "device",
            operation: "remove",
            pool: "tank",
            pool_uuid: Some([0xab; 16]),
            json: false,
            args: live_admin_args([("device_path", LivePoolAdminArg::String("/dev/sdc".into()))]),
        };

        let request = live_owner_request(&route).unwrap();

        assert_eq!(
            request.pool_uuid.as_deref(),
            Some("abababababababababababababababab")
        );
    }

    #[test]
    fn live_owner_request_omits_pool_uuid_when_unknown() {
        let route = LivePoolRoute {
            command: "pool",
            operation: "status",
            pool: "tank",
            pool_uuid: None,
            json: false,
            args: LivePoolAdminArgs::default(),
        };

        let request = live_owner_request(&route).unwrap();

        assert!(request.pool_uuid.is_none());
    }
}
