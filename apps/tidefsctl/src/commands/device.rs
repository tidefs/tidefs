// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! `tidefsctl device` subcommands: operator-triggered device lifecycle
//! requests routed through TideFS pool authority.
//!
//! ## Media authority
//!
//! Device status routes to the live owner before this module opens any store.
//! Device removal routes only to the reachable mounted pool owner, which owns
//! receipt-backed evacuation and durable topology-label publication. Retired
//! directory object-store evacuation/rebuild arguments fail closed instead of
//! acting as operator pool media.

use std::path::PathBuf;

use clap::Subcommand;

/// Device management subcommands.
#[derive(Subcommand, Debug)]
pub enum DeviceCommand {
    /// Remove a device from a pool.
    ///
    /// Routed to the live owner for receipt-backed evacuation and detach.
    Remove {
        /// Pool whose live-owner detach authority is required.
        pool_name: String,

        /// Path to the block device to remove.
        device_path: PathBuf,

        /// Retired directory object-store backing mode.
        #[arg(
            short = 'b',
            long = "backing-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        backing_dir: Option<PathBuf>,

        /// Retired directory object-store survivor mode.
        #[arg(
            short = 'S',
            long = "surviving-dirs",
            hide = true,
            value_delimiter = ',',
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        surviving_dirs: Vec<PathBuf>,
    },

    /// Query live device status with source classification.
    ///
    /// Imported pools route to the live owner; fail closed when
    /// no live owner is reachable.
    Status {
        /// Pool name for live-owner routing.
        pool_name: String,

        /// Output as JSON.
        #[arg(long = "json")]
        json: bool,
    },
    /// Retired directory object-store device rebuild mode.
    #[command(hide = true)]
    Rebuild {
        /// Retired directory object-store survivor mode.
        #[arg(
            short = 'S',
            long = "surviving-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        surviving_dir: std::path::PathBuf,

        /// Retired directory object-store replacement mode.
        #[arg(
            short = 'r',
            long = "replacement-dir",
            hide = true,
            value_parser = crate::commands::reject_directory_pool_media_value
        )]
        replacement_dir: std::path::PathBuf,
    },
}

/// Handle the `tidefsctl device` subcommand.
pub fn handle_device(cmd: DeviceCommand) {
    match cmd {
        DeviceCommand::Remove {
            pool_name,
            device_path,
            backing_dir,
            surviving_dirs,
        } => {
            let _guard = super::authz::require_local_only("device remove");
            if let Err(e) = handle_remove(
                &pool_name,
                &device_path,
                backing_dir.as_ref(),
                &surviving_dirs,
            ) {
                eprintln!("tidefsctl device remove: {e}");
                std::process::exit(1);
            }
        }

        DeviceCommand::Status { pool_name, json } => {
            handle_device_status(pool_name, json);
        }

        DeviceCommand::Rebuild {
            surviving_dir,
            replacement_dir,
        } => {
            if let Err(e) = handle_rebuild(&surviving_dir, &replacement_dir) {
                eprintln!("tidefsctl device rebuild: {e}");
                std::process::exit(1);
            }
        }
    }
}

fn handle_rebuild(
    surviving_dir: &std::path::PathBuf,
    replacement_dir: &std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    Err(format!(
        "offline directory object-store device rebuild is retired \
         (surviving={}, replacement={}); use live pool repair/rebuild authority \
         over block devices or explicit regular-file development devices",
        surviving_dir.display(),
        replacement_dir.display()
    )
    .into())
}

fn handle_remove(
    pool_name: &str,
    device_path: &PathBuf,
    backing_dir: Option<&PathBuf>,
    surviving_dirs: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let online_refusal = online_device_removal_refusal(pool_name, device_path);

    if let Some(backing_dir) = backing_dir {
        return Err(format!(
            "offline device removal through --backing-dir {} is retired; \
             {online_refusal}",
            backing_dir.display(),
        )
        .into());
    }

    if let Some(surviving_dir) = surviving_dirs.first() {
        return Err(format!(
            "offline device removal through --surviving-dirs {} is retired; \
             {online_refusal}",
            surviving_dir.display()
        )
        .into());
    }

    super::live_owner::route_if_owner_exists_with_format_and_args(
        "device",
        "remove",
        pool_name,
        false,
        super::live_owner::live_admin_args([
            (
                "device_path",
                tidefs_vfs_engine::LivePoolAdminArg::String(device_path.display().to_string()),
            ),
            ("force", tidefs_vfs_engine::LivePoolAdminArg::Bool(false)),
        ]),
    );

    Err(online_refusal.into())
}

fn online_device_removal_refusal(pool_name: &str, device_path: &PathBuf) -> String {
    format!(
        "online device removal for pool '{pool_name}' device '{}' requires a reachable live owner; none was found, so no device state was changed. Retry while the pool is mounted. Device removal does not establish secure erase, media-remanence, or decommissioning guarantees.",
        device_path.display()
    )
}

/// Query live device status through the live owner, or fail closed
/// with source-classified refusal when no live owner is reachable.
fn handle_device_status(pool_name: String, json: bool) {
    super::live_owner::route_status_if_owner_exists("device", "status", &pool_name, json);
    super::live_owner::refuse_no_live_status_evidence("device", "status", &pool_name, json);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_without_live_owner_refuses_without_mutation() {
        let result = handle_remove("testpool", &PathBuf::from("/dev/disk0"), None, &[]);

        assert!(result.is_err(), "online removal requires a live owner");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("requires a reachable live owner")
                && msg.contains("none was found")
                && msg.contains("no device state was changed")
                && msg.contains("Retry while the pool is mounted")
                && msg.contains("does not establish secure erase")
                && msg.contains("media-remanence")
                && msg.contains("decommissioning guarantees"),
            "expected unavailable-owner refusal, got {msg}"
        );
    }

    #[test]
    fn removal_with_offline_backing_dir_fails_before_store_open() {
        let dir = tempfile::tempdir().unwrap();
        let target_dir = dir.path().join("missing-target");

        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/disk0"),
            Some(&target_dir),
            &[],
        );

        assert!(result.is_err(), "offline target store must fail closed");
        assert!(
            !target_dir.exists(),
            "retired offline removal must not create or open target stores"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("offline device removal through --backing-dir"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("requires a reachable live owner")
                && msg.contains("no device state was changed"),
            "retired mode must report the shared no-mutation boundary: {msg}"
        );
    }

    #[test]
    fn removal_with_surviving_dirs_fails_before_store_open() {
        let dir = tempfile::tempdir().unwrap();
        let surviving_dir = dir.path().join("missing-survivor");

        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/disk0"),
            None,
            std::slice::from_ref(&surviving_dir),
        );

        assert!(result.is_err(), "offline survivor store must fail closed");
        assert!(
            !surviving_dir.exists(),
            "retired offline removal must not create or open survivor stores"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("offline device removal through --surviving-dirs"),
            "unexpected error: {msg}"
        );
        assert!(
            msg.contains("requires a reachable live owner")
                && msg.contains("no device state was changed"),
            "retired mode must report the shared no-mutation boundary: {msg}"
        );
    }

    #[test]
    fn rebuild_command_fails_closed_before_store_open() {
        let dir = tempfile::tempdir().unwrap();
        let surviving_dir = dir.path().join("surviving-missing");
        let replacement_dir = dir.path().join("replacement-missing");

        let result = handle_rebuild(&surviving_dir, &replacement_dir);

        assert!(result.is_err(), "offline rebuild must fail closed");
        assert!(
            !surviving_dir.exists() && !replacement_dir.exists(),
            "retired rebuild must not create directory-backed stores"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("offline directory object-store device rebuild is retired"),
            "unexpected error: {msg}"
        );
    }
}
