//! Helpers for explicit-device offline pool access.
//!
//! Offline access is deliberately separate from `/run/tidefs/pools`, which is
//! reserved for state owned by an imported runtime.

use std::path::PathBuf;
use std::process;

pub(crate) fn metadata_dir(command: &str, operation: &str, pool_uuid: &[u8; 16]) -> PathBuf {
    let path = std::env::temp_dir()
        .join("tidefs-offline-pools")
        .join(hex_uuid(pool_uuid));
    if let Err(err) = std::fs::create_dir_all(&path) {
        eprintln!(
            "tidefsctl {command} {operation}: cannot create offline pool metadata dir {}: {err}",
            path.display()
        );
        process::exit(1);
    }
    path
}

fn hex_uuid(uuid: &[u8; 16]) -> String {
    uuid.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join("")
}
