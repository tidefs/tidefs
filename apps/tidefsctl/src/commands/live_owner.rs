//! Imported-pool live-owner routing helpers.
//!
//! A pool name is an identity for state already owned by a runtime, not a
//! filesystem path. Explicit storage arguments are not override handles once
//! a kernel, FUSE, or ublk runtime owns the imported pool.

use std::process;

#[derive(Debug, Clone, Copy)]
pub(crate) struct LivePoolRoute<'a> {
    pub(crate) command: &'a str,
    pub(crate) operation: &'a str,
    pub(crate) pool: &'a str,
    pub(crate) pool_uuid: Option<[u8; 16]>,
}

pub(crate) trait LivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> !;
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct MissingLivePoolOwnerClient;

impl LivePoolOwnerClient for MissingLivePoolOwnerClient {
    fn route_live_pool(self, route: LivePoolRoute<'_>) -> ! {
        exit_unavailable(route)
    }
}

pub(crate) fn route(command: &str, operation: &str, pool: &str) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: None,
    })
}

pub(crate) fn route_imported(command: &str, operation: &str, pool: &str, pool_uuid: [u8; 16]) -> ! {
    MissingLivePoolOwnerClient.route_live_pool(LivePoolRoute {
        command,
        operation,
        pool,
        pool_uuid: Some(pool_uuid),
    })
}

fn exit_unavailable(route: LivePoolRoute<'_>) -> ! {
    let command = route.command;
    let operation = route.operation;
    let pool = route.pool;
    eprintln!(
        "tidefsctl {command} {operation}: pool '{pool}' is an imported-pool identity, not a backing path"
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

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
