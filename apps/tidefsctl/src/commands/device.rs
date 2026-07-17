// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! `tidefsctl device` subcommands: operator-triggered device lifecycle
//! requests routed through TideFS pool authority.
//!
//! ## Media authority
//!
//! Device status routes to the live owner before this module opens any store.
//! Device removal currently fails closed before live-owner dispatch because the
//! mounted path cannot yet publish evacuation evidence together with durable,
//! replayable topology-label updates. Retired directory object-store
//! evacuation/rebuild arguments also fail closed instead of acting as operator
//! pool media.

use std::path::PathBuf;
use std::process;

use clap::Subcommand;

/// Device management subcommands.
#[derive(Subcommand, Debug)]
pub enum DeviceCommand {
    /// Remove a device from a pool.
    ///
    /// Refused until the live owner can publish durable detach evidence.
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

        /// Replication factor for failure-domain separation (default: 2).
        #[arg(long, default_value = "2")]
        replication_factor: u8,

        /// Failure domain level: device, node, rack, or datacenter.
        #[arg(long, default_value = "device")]
        failure_domain: String,

        /// Force removal even if evacuation partially fails.
        #[arg(long)]
        force: bool,
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
            replication_factor,
            failure_domain,
            force,
        } => {
            let _guard = super::authz::require_local_only("device remove");
            if let Err(e) = handle_remove(
                &pool_name,
                &device_path,
                backing_dir.as_ref(),
                &surviving_dirs,
                replication_factor,
                &failure_domain,
                force,
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
    _replication_factor: u8,
    _failure_domain: &str,
    _force: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(backing_dir) = backing_dir {
        return Err(format!(
            "offline device removal through --backing-dir {} is retired; \
             use `tidefsctl device remove {pool_name} {}` against a reachable \
             live owner so placement/refcount authority drives evacuation",
            backing_dir.display(),
            device_path.display()
        )
        .into());
    }

    if let Some(surviving_dir) = surviving_dirs.first() {
        return Err(format!(
            "offline device removal through --surviving-dirs {} is retired; \
             use a reachable live owner for pool '{pool_name}'",
            surviving_dir.display()
        )
        .into());
    }

    Err(format!(
        "online device removal for pool '{pool_name}' device '{}' is refused before contacting a live owner: the mounted removal path cannot yet publish a replayable committed evacuation receipt together with durable topology/label updates. No device state was changed. This refusal is a detach-durability boundary; it does not establish secure erase or media-remanence guarantees.",
        device_path.display()
    )
    .into())
}

/// Query live device status through the live owner, or fail closed
/// with source-classified refusal when no live owner is reachable.
fn handle_device_status(pool_name: String, json: bool) {
    let live_truth =
        super::operator_truth::OperatorTruthCarrier::live_route("device", "status", &pool_name);
    if !json {
        eprintln!("{}", live_truth.live_route_attempt_line());
    }
    super::live_owner::route_status_if_owner_exists("device", "status", &pool_name, json);
    let refusal_truth = super::operator_truth::OperatorTruthCarrier::no_live_refusal(
        "device", "status", &pool_name,
    );
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&refusal_truth.json_value()).unwrap()
        );
        process::exit(1);
    } else {
        for line in refusal_truth.operator_lines() {
            eprintln!("{line}");
        }
        super::live_owner::refuse_no_live_status_evidence("device", "status", &pool_name, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_refuses_before_incomplete_live_owner_mutation() {
        let result = handle_remove(
            "testpool",
            &PathBuf::from("/dev/disk0"),
            None,
            &[],
            2,
            "device",
            false,
        );

        assert!(
            result.is_err(),
            "online removal must fail closed until detach evidence is durable"
        );
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("refused before contacting a live owner")
                && msg.contains("replayable committed evacuation receipt")
                && msg.contains("durable topology/label updates")
                && msg.contains("No device state was changed")
                && msg.contains("does not establish secure erase or media-remanence guarantees"),
            "expected durable-detach refusal, got {msg}"
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
            2,
            "device",
            false,
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
            msg.contains("placement/refcount authority"),
            "unexpected error: {msg}"
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
            2,
            "device",
            false,
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

    // -- device status tests --

    #[test]
    fn device_status_routes_to_live_owner_by_pool_name() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::DeviceCommand,
        }
        let args = TestCli::try_parse_from(["test", "status", "testpool"]);
        assert!(args.is_ok(), "device status with pool name should parse");
    }

    #[test]
    fn device_status_accepts_json_flag() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::DeviceCommand,
        }
        let args = TestCli::try_parse_from(["test", "status", "testpool", "--json"]);
        assert!(args.is_ok(), "device status --json should parse");
    }

    #[test]
    fn device_status_rejects_missing_pool_name() {
        use clap::Parser;
        #[derive(Parser, Debug)]
        struct TestCli {
            #[command(subcommand)]
            cmd: super::DeviceCommand,
        }
        let args = TestCli::try_parse_from(["test", "status"]);
        assert!(
            args.is_err(),
            "device status without pool name must be rejected"
        );
    }

    #[test]
    fn device_status_truth_carrier_refuses_without_live_owner() {
        let carrier = super::super::operator_truth::OperatorTruthCarrier::no_live_refusal(
            "device", "status", "testpool",
        );
        let lines = carrier.operator_lines();
        let json = carrier.json_value();

        assert!(lines
            .iter()
            .any(|line| line.contains("evidence:   refused")));
        assert_eq!(json["freshness"], "fresh.truth_view.refused.f4");
        assert_eq!(json["source"], "source.truth_view.runtime_mirror.a2");
    }
}
