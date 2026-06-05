#![forbid(unsafe_code)]

//! TideFS operator CLI.
//!
//! # Command classification
//!
//! | Command | Stage |
//! |---|---|
//! | `mount` | userspace harness (FUSE daemon launch) |
//! | `pool create/scan/status/import/export/destroy` | operator commands |
//! | `pool get/set/list-props` | operator commands |
//! | `pool mount` | userspace harness (pool import + FUSE daemon launch) |
//! | `pool integrity-check` | operator diagnostic |
//! | `snapshot create/list/destroy/rollback/send/receive` | operator commands |
//! | `device remove` | operator command; TFR-012 remains open |
//! | `device rebuild` | operator command; TFR-012 remains open |
//! | `defrag` | operator command |
//! | `block attach/detach/list/send/receive` | operator commands |
//! | `dataset create/list/destroy/rename` | operator command (catalog-backed) |
//! | `dataset set-strategy/seal-key/rotate-key/upgrade/get/set/list-props` | operator commands |
//! | `diag` | operator diagnostic/support bundle |
//! | `cluster pool create` | cluster operator prototype; TFR-017 remains open |
//! | `cluster placement exercise` | development diagnostic exercise |
//! | `cluster heal exercise` | development diagnostic exercise |
//!
//! # Pool owner routing
//!
//! Imported-pool commands must talk to the runtime owner for live state:
//! the declared kernel UAPI in kernel mode, or the FUSE/ublk owner in
//! userspace mode. Explicit device or backing-directory arguments are for
//! offline, discovery, import, or not-yet-imported work; they are not an
//! override once the pool is imported. Do not make pool-name usability by
//! reopening runtime metadata behind the live owner.
mod commands;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use tidefs_posix_filesystem_adapter_daemon::coherency_profile::CoherencyProfile;
use tidefs_posix_filesystem_adapter_daemon::{self, MountConfig};

#[derive(Parser, Debug)]
#[command(
    name = "tidefsctl",
    version = env!("CARGO_PKG_VERSION"),
    about = "TideFS operator CLI and development harnesses",
    long_about = r#"TideFS command-line interface.

Primary operator groups:
  pool      create, discover, import/export, inspect, and tune pools
  dataset   manage the pool-wide dataset catalog and dataset properties
  snapshot  create, list, destroy, roll back, send, and receive snapshots
  device    remove or rebuild pool devices
  block     attach, list, detach, send, and receive ublk block devices
  diag      collect a redacted support bundle

Development harnesses:
  mount                         launch the current FUSE harness
  pool mount                    import a pool and launch the FUSE harness
  cluster placement exercise    run placement diagnostics
  cluster heal exercise         run healing diagnostics

Pool routing rule:
  A pool name identifies an imported pool. Imported state is cached and must
  be queried or changed through the live owner: the kernel UAPI in kernel
  mode, or the userspace daemon owner in userspace mode. Explicit --devices
  or --backing-dir inputs are for offline, discovery, import, or
  not-yet-imported work, not overrides for an imported pool.

TideFS is pre-alpha. Help text should mark harnesses as such instead of
treating them as the final kernel runtime."#,
    after_help = "Start with `tidefsctl pool --help`, `tidefsctl dataset --help`, or `tidefsctl diag --help`. The book source lives under docs/book/.",
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Launch the FUSE development mount harness
    Mount {
        /// Backing directory for local object store
        backing_dir: PathBuf,

        /// FUSE mountpoint directory
        mountpoint: PathBuf,

        /// Run in foreground (default)
        #[arg(long)]
        foreground: bool,

        /// Enable debug output
        #[arg(long)]
        debug: bool,

        /// Dataset path to mount (default "root"). Resolved through the dataset catalog.
        #[arg(long = "dataset", default_value = "root")]
        dataset: String,

        /// Path to a sealed pool key envelope file (84 bytes, "VEKF" magic).
        /// When set, the pool is opened with per-object encryption.
        #[arg(long = "encryption-envelope", value_name = "PATH")]
        encryption_envelope: Option<PathBuf>,
    },

    /// Manage pools; includes the pool-backed FUSE harness
    Pool {
        #[command(subcommand)]
        cmd: commands::pool::PoolCommand,
    },

    /// Manage devices in a TideFS pool
    Device {
        #[command(subcommand)]
        cmd: commands::device::DeviceCommand,
    },
    /// Manage filesystem snapshots
    Snapshot {
        #[command(subcommand)]
        cmd: commands::snapshot::SnapshotCommand,
    },

    /// Manage datasets in the pool-wide catalog
    Dataset {
        #[command(subcommand)]
        cmd: commands::dataset::DatasetCommand,
    },

    /// Trigger online extent map defragmentation
    Defrag {
        /// Path to file or directory to defrag
        path: PathBuf,

        /// Recursively defrag all files under a directory
        #[arg(long)]
        recursive: bool,
    },

    /// Manage cluster prototypes and development diagnostics
    Cluster {
        #[command(subcommand)]
        cmd: commands::cluster::ClusterCommand,
    },

    /// Manage ublk block devices backed by a TideFS pool
    Block {
        #[command(subcommand)]
        cmd: commands::block::BlockCommand,
    },

    /// Collect a redacted support bundle
    Diag {
        /// Output directory for the support bundle JSON file
        #[arg(long = "output", short = 'o', value_name = "DIR")]
        output_dir: Option<PathBuf>,

        /// Device paths to scan for pool information
        #[arg(long = "devices", value_name = "DEVICES", num_args = 1..)]
        devices: Vec<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Command::Mount {
            backing_dir,
            mountpoint,
            foreground,
            debug,
            dataset,
            encryption_envelope,
        } => handle_mount(
            backing_dir,
            mountpoint,
            foreground,
            debug,
            dataset,
            encryption_envelope,
        ),

        Command::Pool { cmd } => commands::pool::handle_pool(cmd),

        Command::Defrag { path, recursive } => commands::defrag::handle_defrag(&path, recursive),
        Command::Block { cmd } => commands::block::handle_block(cmd),
        Command::Device { cmd } => commands::device::handle_device(cmd),
        Command::Snapshot { cmd } => commands::snapshot::handle_snapshot(cmd),
        Command::Dataset { cmd } => commands::dataset::handle_dataset(cmd),

        Command::Diag {
            output_dir,
            devices,
        } => commands::diag::handle_diag(output_dir, &devices),
        Command::Cluster { cmd } => commands::cluster::handle_cluster(cmd),
    }
}

fn handle_mount(
    backing_dir: PathBuf,
    mountpoint: PathBuf,
    foreground: bool,
    debug: bool,
    dataset: String,
    encryption_envelope: Option<PathBuf>,
) {
    let encryption_config = if let Some(ref envelope_path) = encryption_envelope {
        let root_auth_key = tidefs_local_filesystem::RootAuthenticationKey::from_environment()
            .unwrap_or_else(|_| tidefs_local_filesystem::RootAuthenticationKey::demo_key());
        match tidefs_posix_filesystem_adapter_daemon::resolve_encryption_key_from_envelope(
            envelope_path,
            &root_auth_key,
        ) {
            Some(config) => Some(config),
            None => {
                eprintln!(
                    "tidefsctl mount: failed to unseal encryption envelope {}",
                    envelope_path.display()
                );
                eprintln!(
                    "tidefsctl mount: wrong root auth key, corrupt envelope, or tampered file"
                );
                process::exit(1);
            }
        }
    } else {
        None
    };

    let config = MountConfig {
        backing_dir,
        mountpoint,
        pool_name: None,
        pool_uuid: None,
        foreground,
        debug,
        writeback_cache: false,
        coherency_profile: CoherencyProfile::Writeback,
        block_devices: None,
        dataset_path: Some(dataset),
        encryption: encryption_config,
        cluster_authorized: false,
        cluster_lease_token_bytes: None,
    };

    if let Err(err) = tidefs_posix_filesystem_adapter_daemon::run_mount(config) {
        eprintln!("tidefsctl mount: {err}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parse_mount_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "mount", "/tmp/backing", "/tmp/mountpoint"]);
        assert!(args.is_ok(), "mount with two positional args should parse");
    }

    #[test]
    fn cli_parse_mount_with_flags() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "mount",
            "/tmp/backing",
            "/tmp/mountpoint",
            "--foreground",
            "--debug",
        ]);
        assert!(args.is_ok(), "mount with flags should parse");
    }

    #[test]
    fn cli_parse_pool_create_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "create",
            "testpool",
            "--devices",
            "/dev/sda",
        ]);
        assert!(args.is_ok(), "pool create with minimum args should parse");
    }

    #[test]
    fn cli_parse_pool_create_multiple_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "create",
            "testpool",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
            "/dev/sdc",
            "--redundancy",
            "mirror",
        ]);
        assert!(
            args.is_ok(),
            "pool create with multiple devices should parse"
        );
    }

    #[test]
    fn cli_parse_pool_create_all_options() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "create",
            "bigpool",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
            "--redundancy",
            "mirror",
            "--feature-flags",
            "encryption,compression",
        ]);
        assert!(args.is_ok(), "pool create with all options should parse");
    }

    #[test]
    fn cli_parse_pool_create_rejects_no_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "create", "testpool"]);
        assert!(args.is_err(), "pool create without --devices should fail");
    }

    #[test]
    fn cli_parse_pool_list_is_not_exposed() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "list"]);
        assert!(
            args.is_err(),
            "pool list should not parse without a real pool registry"
        );
    }

    #[test]
    fn cli_parse_pool_scan_default() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "scan",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
        ]);
        assert!(args.is_ok(), "pool scan with --devices should parse");
    }

    #[test]
    fn cli_parse_pool_scan_rejects_no_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "scan"]);
        assert!(args.is_err(), "pool scan without --devices should fail");
    }

    #[test]
    fn cli_parse_pool_status_default() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "status", "mypool"]);
        assert!(args.is_ok(), "pool status with name should parse");
    }

    #[test]
    fn cli_parse_pool_status_json() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "status", "mypool", "--json"]);
        assert!(args.is_ok(), "pool status --json should parse");
    }

    #[test]
    fn cli_parse_pool_status_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "status"]);
        assert!(args.is_err(), "pool status without name should fail");
    }

    #[test]
    fn cli_parse_pool_status_with_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "status",
            "mypool",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
        ]);
        assert!(args.is_ok(), "pool status with --devices should parse");
    }

    #[test]
    fn cli_parse_pool_property_commands_use_positional_pool() {
        use clap::Parser;
        let get = Cli::try_parse_from(["tidefsctl", "pool", "get", "mypool", "space.quota"]);
        assert!(get.is_ok(), "pool get with positional pool should parse");

        let set = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "set",
            "mypool",
            "space.quota=1073741824",
        ]);
        assert!(set.is_ok(), "pool set with positional pool should parse");

        let list = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "list-props",
            "mypool",
            "--family",
            "space",
        ]);
        assert!(
            list.is_ok(),
            "pool list-props with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_pool_property_commands_reject_pool_flag() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "get",
            "space.quota",
            "--pool",
            "mypool",
        ]);
        assert!(args.is_err(), "pool get --pool should not parse");
    }

    #[test]
    fn cli_parse_pool_destroy_default() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "destroy",
            "mypool",
            "--devices",
            "/dev/sda",
        ]);
        assert!(
            args.is_ok(),
            "pool destroy with name and devices should parse"
        );
    }

    #[test]
    fn cli_parse_pool_destroy_force() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "destroy",
            "mypool",
            "--devices",
            "/dev/sda",
            "--force",
        ]);
        assert!(args.is_ok(), "pool destroy --force should parse");
    }

    #[test]
    fn cli_parse_pool_destroy_zero_superblock() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "destroy",
            "mypool",
            "--devices",
            "/dev/sda",
            "--zero-superblock",
        ]);
        assert!(args.is_ok(), "pool destroy --zero-superblock should parse");
    }

    #[test]
    fn cli_parse_pool_destroy_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "destroy"]);
        assert!(args.is_err(), "pool destroy without name should fail");
    }

    #[test]
    fn cli_parse_pool_destroy_rejects_no_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "destroy", "mypool"]);
        assert!(args.is_err(), "pool destroy without --devices should fail");
    }

    #[test]
    fn cli_parse_unknown_command_rejected() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "nonexistent"]);
        assert!(args.is_err(), "unknown command should fail");
    }

    #[test]
    fn cli_help_flag_works() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "--help"]);
        assert!(args.is_err() || args.is_ok(), "--help should not panic");
    }

    #[test]
    fn cli_parse_pool_import_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import", "/dev/sda"]);
        assert!(args.is_ok(), "pool import with one device should parse");
    }

    #[test]
    fn cli_parse_pool_import_multiple_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "import",
            "/dev/sda",
            "/dev/sdb",
            "/dev/sdc",
        ]);
        assert!(
            args.is_ok(),
            "pool import with multiple devices should parse"
        );
    }

    #[test]
    fn cli_parse_pool_import_read_only() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import", "--read-only", "/dev/sda"]);
        assert!(args.is_ok(), "pool import --read-only should parse");
    }

    #[test]
    fn cli_parse_pool_import_lock_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "import",
            "--lock-dir",
            "/tmp/locks",
            "/dev/sda",
        ]);
        assert!(args.is_ok(), "pool import --lock-dir should parse");
    }

    #[test]
    fn cli_parse_pool_import_rejects_no_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import"]);
        assert!(args.is_err(), "pool import without devices should fail");
    }

    // ── Pool export CLI parse tests ─────────────────────────────────

    #[test]
    fn cli_parse_pool_export_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "export", "mypool"]);
        assert!(args.is_ok(), "pool export with name should parse");
    }

    #[test]
    fn cli_parse_pool_export_force() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "export", "mypool", "--force"]);
        assert!(args.is_ok(), "pool export --force should parse");
    }

    #[test]
    fn cli_parse_pool_export_with_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "export",
            "mypool",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
        ]);
        assert!(args.is_ok(), "pool export with --devices should parse");
    }

    #[test]
    fn cli_parse_pool_export_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "export"]);
        assert!(args.is_err(), "pool export without name should fail");
    }

    // -- Snapshot CLI parse tests -----------------------------------------

    #[test]
    fn cli_parse_snapshot_create_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "create",
            "mysnap",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(
            args.is_ok(),
            "snapshot create with name and backing-dir should parse"
        );
    }

    #[test]
    fn cli_parse_snapshot_create_live_pool_positional() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "snapshot", "create", "mypool", "mysnap"]);
        assert!(
            args.is_ok(),
            "snapshot create with positional pool and name should parse"
        );
    }

    #[test]
    fn cli_parse_snapshot_list_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "list",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(args.is_ok(), "snapshot list with backing-dir should parse");
    }

    #[test]
    fn cli_parse_snapshot_list_live_pool_positional() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "snapshot", "list", "mypool"]);
        assert!(
            args.is_ok(),
            "snapshot list with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_snapshot_rejects_pool_flag() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "snapshot", "list", "--pool", "mypool"]);
        assert!(args.is_err(), "snapshot list --pool should not parse");
    }

    #[test]
    fn cli_parse_snapshot_destroy_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "destroy",
            "mysnap",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(
            args.is_ok(),
            "snapshot destroy with name and backing-dir should parse"
        );
    }

    #[test]
    fn cli_parse_snapshot_destroy_live_pool_positional() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "snapshot", "destroy", "mypool", "mysnap"]);
        assert!(
            args.is_ok(),
            "snapshot destroy with positional pool and name should parse"
        );
    }

    #[test]
    fn cli_parse_snapshot_destroy_short_flag() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "destroy",
            "mysnap",
            "-b",
            "/tmp/pool",
        ]);
        assert!(args.is_ok(), "snapshot destroy with -b flag should parse");
    }

    #[test]
    fn cli_parse_snapshot_destroy_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "destroy",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(args.is_err(), "snapshot destroy without name should fail");
    }

    #[test]
    fn cli_parse_snapshot_destroy_rejects_no_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "snapshot", "destroy"]);
        assert!(
            args.is_err(),
            "snapshot destroy without operands should fail"
        );
    }

    // -- Dataset CLI parse tests ------------------------------------------

    #[test]
    fn cli_parse_dataset_create_positional_pool() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "dataset", "create", "mypool", "data"]);
        assert!(
            args.is_ok(),
            "dataset create with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_list_positional_pool() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "dataset", "list", "mypool"]);
        assert!(
            args.is_ok(),
            "dataset list with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_set_strategy_positional_pool() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "set-strategy",
            "mypool",
            "data",
            "--enable",
            "org.tidefs:compression_zstd",
        ]);
        assert!(
            args.is_ok(),
            "dataset set-strategy with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_rejects_pool_flag() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "dataset", "list", "--pool", "mypool"]);
        assert!(args.is_err(), "dataset list --pool should not parse");
    }

    // ── Pool mount CLI parse tests ─────────────────────────────────

    #[test]
    fn cli_parse_pool_mount_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "mount", "testpool", "/mnt/tidefs"]);
        assert!(
            args.is_ok(),
            "pool mount with pool name and mount point should parse"
        );
    }

    #[test]
    fn cli_parse_pool_mount_read_only() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--read-only",
        ]);
        assert!(args.is_ok(), "pool mount --read-only should parse");
    }

    #[test]
    fn cli_parse_pool_mount_relatime() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--relatime",
        ]);
        assert!(args.is_ok(), "pool mount --relatime should parse");
    }

    #[test]
    fn cli_parse_pool_mount_all_flags() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--read-only",
            "--relatime",
        ]);
        assert!(args.is_ok(), "pool mount with all flags should parse");
    }

    #[test]
    fn cli_parse_pool_mount_rejects_no_mount_point() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "mount", "testpool"]);
        assert!(args.is_err(), "pool mount without mount point should fail");
    }

    #[test]
    fn cli_parse_pool_mount_rejects_no_args() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "mount"]);
        assert!(args.is_err(), "pool mount without args should fail");
    }

    // ── Pool integrity-check CLI parse tests ─────────────────────────

    #[test]
    fn cli_parse_pool_integrity_check_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "integrity-check", "/tmp/pool"]);
        assert!(
            args.is_ok(),
            "pool integrity-check with backing dir should parse"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_json() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "/tmp/pool",
            "--json",
        ]);
        assert!(args.is_ok(), "pool integrity-check --json should parse");
    }

    #[test]
    fn cli_parse_pool_integrity_check_max_records() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "/tmp/pool",
            "--max-records",
            "100",
        ]);
        assert!(
            args.is_ok(),
            "pool integrity-check --max-records should parse"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_max_bytes() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "/tmp/pool",
            "--max-bytes",
            "1048576",
        ]);
        assert!(
            args.is_ok(),
            "pool integrity-check --max-bytes should parse"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_all_flags() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "/tmp/pool",
            "--json",
            "--max-records",
            "1000",
            "--max-bytes",
            "1048576",
        ]);
        assert!(
            args.is_ok(),
            "pool integrity-check with all flags should parse"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_rejects_no_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "integrity-check"]);
        assert!(
            args.is_err(),
            "pool integrity-check without backing dir should fail"
        );
    }
}
