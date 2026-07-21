// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
mod authz;
pub mod block;
pub mod classification;
pub mod cluster;
pub mod dataset;
pub mod defrag;
pub mod device;
pub mod diag;
pub mod kernel;
mod live_owner;
pub mod merge;
pub mod mount;
mod offline_pool;
pub mod pool;
pub mod snapshot;
pub mod storage_intent;

#[cfg(test)]
pub(crate) use authz::command_surface_authority_table;

pub(crate) use offline_pool::refuse_runtime_pool_path;

use std::path::PathBuf;
use std::process;

use tidefs_local_filesystem::{RootAuthenticationKey, ROOT_AUTHENTICATION_ENV_VAR};

#[cfg(test)]
pub(crate) fn with_root_auth_env<T>(value: Option<&str>, run: impl FnOnce() -> T) -> T {
    use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    let guard = env_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let previous = std::env::var_os(ROOT_AUTHENTICATION_ENV_VAR);
    match value {
        Some(value) => std::env::set_var(ROOT_AUTHENTICATION_ENV_VAR, value),
        None => std::env::remove_var(ROOT_AUTHENTICATION_ENV_VAR),
    }

    let result = catch_unwind(AssertUnwindSafe(run));

    match previous {
        Some(previous) => std::env::set_var(ROOT_AUTHENTICATION_ENV_VAR, previous),
        None => std::env::remove_var(ROOT_AUTHENTICATION_ENV_VAR),
    }

    drop(guard);

    match result {
        Ok(result) => result,
        Err(payload) => resume_unwind(payload),
    }
}

pub(crate) fn required_root_authentication_key(
    operation: &str,
) -> Result<RootAuthenticationKey, String> {
    RootAuthenticationKey::from_environment().map_err(|err| {
        format!(
            "tidefsctl {operation}: root authentication key is required: {err}; set {ROOT_AUTHENTICATION_ENV_VAR} to a 64-hex-character key"
        )
    })
}

pub(crate) fn root_authentication_key_or_exit(operation: &str) -> RootAuthenticationKey {
    match required_root_authentication_key(operation) {
        Ok(key) => key,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}

pub(crate) fn reject_directory_pool_media_value(raw: &str) -> Result<PathBuf, String> {
    Err(retired_directory_pool_media_message(raw))
}

pub(crate) fn retired_directory_pool_media_message(raw: &str) -> String {
    format!(
        "directory-backed object-store pool media `{raw}` is retired; use a pool name routed to the live owner, or explicit --devices block-device / regular-file development pool media where offline access is supported"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_root_authentication_key_rejects_missing_env() {
        with_root_auth_env(None, || {
            let err = required_root_authentication_key("test operation").unwrap_err();
            assert!(err.contains(ROOT_AUTHENTICATION_ENV_VAR));
            assert!(err.contains("missing"));
        });
    }

    #[test]
    fn required_root_authentication_key_rejects_malformed_env() {
        with_root_auth_env(Some("not-hex"), || {
            let err = required_root_authentication_key("test operation").unwrap_err();
            assert!(err.contains(ROOT_AUTHENTICATION_ENV_VAR));
            assert!(err.contains("invalid"));
        });
    }

    #[test]
    fn required_root_authentication_key_accepts_valid_env() {
        let valid = "a".repeat(64);
        with_root_auth_env(Some(&valid), || {
            required_root_authentication_key("test operation").unwrap();
        });
    }
}
