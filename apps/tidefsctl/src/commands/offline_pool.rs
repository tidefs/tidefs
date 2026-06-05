//! Helpers for explicit-device offline pool access.
//!
//! Offline access is deliberately separate from `/run/tidefs/pools`, which is
//! reserved for state owned by an imported runtime.

use std::path::{Path, PathBuf};
use std::process;

const RUNTIME_POOL_ROOT: &str = "/run/tidefs/pools";

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

pub(crate) fn refuse_runtime_pool_path(command: &str, operation: &str, path: &Path) {
    if !is_runtime_pool_path(path) {
        return;
    }
    eprintln!(
        "tidefsctl {command} {operation}: {} is imported-pool runtime state",
        path.display()
    );
    eprintln!(
        "tidefsctl {command} {operation}: live state must be requested through the kernel UAPI or userspace daemon owner"
    );
    eprintln!(
        "tidefsctl {command} {operation}: use a pool name for imported pools, or an offline/exported backing directory outside {RUNTIME_POOL_ROOT}"
    );
    process::exit(1);
}

pub(crate) fn is_runtime_pool_path(path: &Path) -> bool {
    let root = Path::new(RUNTIME_POOL_ROOT);
    if let (Ok(canonical_path), Ok(canonical_root)) =
        (std::fs::canonicalize(path), std::fs::canonicalize(root))
    {
        if canonical_path == canonical_root || canonical_path.starts_with(&canonical_root) {
            return true;
        }
    }

    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(_) => path.to_path_buf(),
        }
    };
    absolute == root || absolute.starts_with(root)
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
    fn runtime_pool_paths_are_not_offline_paths() {
        assert!(is_runtime_pool_path(Path::new("/run/tidefs/pools")));
        assert!(is_runtime_pool_path(Path::new(
            "/run/tidefs/pools/0123456789abcdef"
        )));
        assert!(!is_runtime_pool_path(Path::new("/run/tidefs/pools-other")));
        assert!(!is_runtime_pool_path(Path::new("/var/lib/tidefs/tank")));
    }
}
