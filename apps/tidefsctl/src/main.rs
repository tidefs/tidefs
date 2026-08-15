// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
#![forbid(unsafe_code)]

//! TideFS operator CLI.
//!
//! # Command classification
//!
//! The source of truth lives in
//! [`commands::classification::COMMAND_SURFACES`]. Help text, docs, and claim
//! gates consume or check that registry instead of keeping a separate command
//! maturity table.
//!
//! # Pool owner routing
//!
//! Imported-pool commands must talk to the runtime owner for live state:
//! the declared kernel UAPI in kernel mode, or the FUSE/ublk owner in
//! userspace mode. Explicit device arguments are for offline, discovery,
//! import, or not-yet-imported work; they are not an override once the pool is
//! imported. Do not make pool-name usability by reopening runtime metadata
//! behind the live owner.
mod commands;
mod parser;

use std::path::PathBuf;
use std::process;

use clap::{Parser, Subcommand};

use tidefs_posix_filesystem_adapter_daemon::coherency_profile::CoherencyProfile;
use tidefs_posix_filesystem_adapter_daemon::{self, MountAuthority, MountConfig};

#[derive(Parser, Debug)]
#[command(
    name = "tidefsctl",
    version = env!("CARGO_PKG_VERSION"),
    about = "TideFS operator CLI and development harnesses",
    long_about = commands::classification::root_long_about(),
    after_help = commands::classification::root_after_help(),
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
    /// Manage filesystem/volume snapshots and writable volume clones
    Snapshot {
        #[command(subcommand)]
        cmd: commands::snapshot::SnapshotCommand,
    },

    /// Manage datasets in the pool-wide catalog
    Dataset {
        #[command(subcommand)]
        cmd: commands::dataset::DatasetCommand,
    },

    #[cfg(feature = "storage-intent")]
    /// Explain supplied storage-intent policy, receipt, and evidence records
    StorageIntent {
        #[command(subcommand)]
        cmd: commands::storage_intent::StorageIntentCommand,
    },

    /// Trigger online extent map defragmentation
    Defrag {
        /// Path to file or directory to defrag
        path: PathBuf,

        /// Recursively defrag all files under a directory
        #[arg(long)]
        recursive: bool,
    },

    #[cfg(feature = "cluster")]
    /// Manage cluster prototypes and development diagnostics
    Cluster {
        #[command(subcommand)]
        cmd: commands::cluster::ClusterCommand,
    },

    #[cfg(feature = "block-volume")]
    /// Manage ublk block devices backed by a TideFS pool
    Block {
        #[command(subcommand)]
        cmd: commands::block::BlockCommand,
    },

    #[cfg(feature = "diagnostics")]
    /// Inspect kernel-resident TideFS control surfaces
    Kernel {
        #[command(subcommand)]
        cmd: commands::kernel::KernelCommand,
    },

    #[cfg(feature = "receive-merge")]
    /// Resolve merge conflicts for receive merge planner manual policy
    Merge {
        #[command(subcommand)]
        cmd: commands::merge::MergeCommand,
    },
    #[cfg(feature = "diagnostics")]
    /// Collect a redacted support bundle
    Diag {
        /// Output directory for the support bundle JSON file
        #[arg(long = "output", short = 'o', value_name = "DIR")]
        output_dir: Option<PathBuf>,

        /// Print the source-qualified support bundle JSON to stdout
        #[arg(long = "json")]
        json: bool,

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
        #[cfg(feature = "block-volume")]
        Command::Block { cmd } => commands::block::handle_block(cmd),
        Command::Device { cmd } => commands::device::handle_device(cmd),
        Command::Snapshot { cmd } => commands::snapshot::handle_snapshot(cmd),
        Command::Dataset { cmd } => commands::dataset::handle_dataset(cmd),
        #[cfg(feature = "storage-intent")]
        Command::StorageIntent { cmd } => commands::storage_intent::handle_storage_intent(cmd),

        #[cfg(feature = "diagnostics")]
        Command::Diag {
            output_dir,
            json,
            devices,
        } => commands::diag::handle_diag(output_dir, &devices, json),
        #[cfg(feature = "cluster")]
        Command::Cluster { cmd } => commands::cluster::handle_cluster(cmd),
        #[cfg(feature = "diagnostics")]
        Command::Kernel { cmd } => commands::kernel::handle_kernel(cmd),
        #[cfg(feature = "receive-merge")]
        Command::Merge { cmd } => commands::merge::handle_merge(cmd),
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
    commands::refuse_runtime_pool_path("mount", "mount", &backing_dir);

    let encryption_config = if let Some(ref envelope_path) = encryption_envelope {
        let root_auth_key = commands::root_authentication_key_or_exit("mount");
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
        pool_redundancy_policy: tidefs_local_object_store::PoolRedundancyPolicy::default(),
        pool_uuid: None,
        foreground,
        debug,
        read_only: false,
        writeback_cache: false,
        coherency_profile: CoherencyProfile::Writeback,
        block_devices: None,
        import_owner: None,
        dataset_path: Some(dataset),
        encryption: encryption_config,
        snapshot_name: None,
        mount_authority: MountAuthority::standalone(),
        runtime: tidefs_posix_filesystem_adapter_daemon::MountRuntimeOptions::default(),
    };

    if let Err(err) = tidefs_posix_filesystem_adapter_daemon::run_mount(config) {
        eprintln!("tidefsctl mount: {err}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn render_long_help(mut command: clap::Command) -> String {
        let mut buf = Vec::new();
        command.write_long_help(&mut buf).expect("render help");
        String::from_utf8(buf).expect("help should be UTF-8")
    }

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
            "replicated=2",
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
            "replicated=2",
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
    fn cli_parse_pool_list_as_hidden_removed_surface() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "list"]);
        assert!(
            args.is_ok(),
            "pool list is a hidden removed surface so it can fail with a clear runtime error"
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
        let args = Cli::try_parse_from(["tidefsctl", "pool", "destroy", "mypool"]);
        assert!(
            args.is_ok(),
            "pool destroy with positional pool should route to live owner"
        );
    }

    #[test]
    fn cli_parse_pool_destroy_with_devices() {
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
    fn cli_parse_pool_destroy_json() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "destroy", "mypool", "--json"])
            .expect("pool destroy --json should parse");

        match args.command {
            Command::Pool {
                cmd:
                    commands::pool::PoolCommand::Destroy {
                        pool_name,
                        devices,
                        json,
                        ..
                    },
            } => {
                assert_eq!(pool_name, "mypool");
                assert_eq!(devices, None);
                assert!(json);
            }
            other => panic!("expected pool destroy, got {other:?}"),
        }
    }

    #[test]
    fn cli_parse_pool_destroy_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "destroy"]);
        assert!(args.is_err(), "pool destroy without name should fail");
    }

    #[test]
    fn cli_parse_unknown_command_rejected() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "nonexistent"]);
        assert!(args.is_err(), "unknown command should fail");
    }

    #[cfg(any(
        not(feature = "block-volume"),
        not(feature = "cluster"),
        not(feature = "diagnostics"),
        not(feature = "receive-merge"),
        not(feature = "replication-io"),
        not(feature = "storage-intent")
    ))]
    #[test]
    fn cli_parser_exposes_only_enabled_optional_surfaces() {
        use clap::Parser;

        #[cfg(not(feature = "block-volume"))]
        assert!(Cli::try_parse_from(["tidefsctl", "block", "list"]).is_err());
        #[cfg(not(feature = "cluster"))]
        assert!(Cli::try_parse_from(["tidefsctl", "cluster", "status", "mypool"]).is_err());
        #[cfg(not(feature = "diagnostics"))]
        {
            assert!(Cli::try_parse_from(["tidefsctl", "diag"]).is_err());
            assert!(Cli::try_parse_from(["tidefsctl", "kernel", "status"]).is_err());
        }
        #[cfg(not(feature = "receive-merge"))]
        assert!(Cli::try_parse_from([
            "tidefsctl",
            "merge",
            "show",
            "--inventory",
            "/tmp/inventory.json",
        ])
        .is_err());
        #[cfg(not(feature = "replication-io"))]
        {
            assert!(Cli::try_parse_from(["tidefsctl", "snapshot", "send", "mypool"]).is_err());
            assert!(Cli::try_parse_from(["tidefsctl", "snapshot", "receive", "mypool"]).is_err());
        }
        #[cfg(not(feature = "storage-intent"))]
        assert!(Cli::try_parse_from(["tidefsctl", "storage-intent"]).is_err());
    }

    #[cfg(any(
        not(feature = "cluster"),
        all(feature = "replication-io", not(feature = "remote-snapshot"))
    ))]
    #[test]
    fn local_commands_hide_disabled_nonlocal_options() {
        use clap::Parser;

        #[cfg(not(feature = "cluster"))]
        {
            assert!(Cli::try_parse_from([
                "tidefsctl",
                "pool",
                "mount",
                "mypool",
                "/mnt/tidefs",
                "--devices",
                "/dev/null",
                "--cluster",
            ])
            .is_err());
            assert!(Cli::try_parse_from(["tidefsctl", "dataset", "list", "--cluster"]).is_err());
        }
        #[cfg(all(feature = "replication-io", not(feature = "remote-snapshot")))]
        assert!(Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "send",
            "mypool",
            "--target-addr",
            "127.0.0.1:9000",
            "--node-id",
            "1",
            "--server-node-id",
            "2",
        ])
        .is_err());
    }

    #[cfg(feature = "storage-intent")]
    #[test]
    fn cli_parse_storage_intent_explain_read_only_surface() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "storage-intent",
            "explain",
            "--dataset",
            "tank/fs",
            "--file",
            "/file",
            "--range",
            "0..4096",
            "--json",
        ]);
        assert!(
            args.is_ok(),
            "storage-intent explain should parse as a read-only operator surface"
        );
    }

    #[cfg(feature = "storage-intent")]
    #[test]
    fn cli_parse_storage_intent_policy_set_surface() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "storage-intent",
            "policy",
            "set",
            "tank/fs",
            "--allow",
            "bounded-readahead,cache-only-trial",
            "--refuse",
            "flash-hot-serving",
            "--max-prefetch-window-bytes",
            "1048576",
            "--budget-owner",
            "dataset-a",
            "--budget",
            "ram=dataset-a",
            "--feedback-mode",
            "prefetch-windows",
            "--json",
        ]);
        assert!(args.is_ok(), "storage-intent policy set should parse");
    }

    #[cfg(feature = "storage-intent")]
    #[test]
    fn cli_parse_storage_intent_policy_clear_and_dry_run_surfaces() {
        use clap::Parser;
        let clear = Cli::try_parse_from([
            "tidefsctl",
            "storage-intent",
            "policy",
            "clear",
            "tank/fs",
            "--all",
            "--json",
        ]);
        assert!(clear.is_ok(), "storage-intent policy clear should parse");

        let dry_run = Cli::try_parse_from([
            "tidefsctl",
            "storage-intent",
            "policy",
            "dry-run",
            "--input",
            "/tmp/source.json",
            "--json",
        ]);
        assert!(
            dry_run.is_ok(),
            "storage-intent policy dry-run should parse"
        );
    }

    #[test]
    fn cli_help_flag_works() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "--help"]);
        assert!(args.is_err() || args.is_ok(), "--help should not panic");
    }

    #[test]
    fn cli_long_help_uses_command_classification() {
        let help = render_long_help(Cli::command());
        assert!(help.contains(commands::classification::COMMAND_CLASSIFICATION_DOC_MARKER));
        assert!(help.contains(commands::classification::COMMAND_CLASSIFICATION_SOURCE_PATH));
        assert!(help.contains("Public operator commands:"));
        assert!(help.contains("Userspace harnesses:"));
        assert!(help.contains("Prototype surfaces:"));
        #[cfg(feature = "cluster")]
        {
            assert!(help.contains("cluster placement exercise"));
            assert!(help.contains("development-exercise"));
            assert!(help.contains("not final distributed operator UAPI"));
        }
        #[cfg(not(feature = "cluster"))]
        assert!(!help.contains("cluster placement exercise"));
        assert!(help.contains("Explicit --devices"));
    }

    #[test]
    fn command_help_hides_removed_surfaces() {
        let pool_command = commands::pool::PoolCommand::command();
        assert!(pool_command
            .get_subcommands()
            .find(|command| command.get_name() == "list")
            .expect("hidden pool list command exists")
            .is_hide_set());
        let pool_help = render_long_help(pool_command);
        assert!(!pool_help
            .lines()
            .any(|line| line.trim_start().starts_with("list ")));

        #[derive(clap::Parser)]
        struct DeviceHelpCli {
            #[command(subcommand)]
            cmd: commands::device::DeviceCommand,
        }

        let device_help = render_long_help(DeviceHelpCli::command());
        assert!(!device_help
            .lines()
            .any(|line| line.trim_start().starts_with("rebuild ")));
    }

    #[cfg(feature = "full")]
    #[test]
    fn preview_uapi_doc_declares_command_classification_contract() {
        let doc_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docs/PREVIEW_UAPI_ABI_BOUNDARY_OW202.md");
        let doc = std::fs::read_to_string(&doc_path).expect("read preview UAPI doc");
        let table = commands::command_surface_authority_table();

        assert!(doc.contains(commands::classification::COMMAND_CLASSIFICATION_DOC_MARKER));
        assert!(doc.contains(commands::classification::COMMAND_CLASSIFICATION_SOURCE_PATH));
        assert!(
            doc.contains(&table),
            "preview UAPI doc must carry the exact command registry/admission table"
        );
    }

    #[test]
    fn cli_parse_pool_import_minimum() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import", "mypool"]);
        assert!(
            args.is_ok(),
            "pool import with positional pool should parse"
        );
    }

    #[test]
    fn cli_parse_pool_import_multiple_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "import",
            "mypool",
            "--devices",
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
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "import",
            "mypool",
            "--read-only",
            "--devices",
            "/dev/sda",
        ]);
        assert!(args.is_ok(), "pool import --read-only should parse");
    }

    #[test]
    fn cli_parse_pool_import_lock_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "import",
            "mypool",
            "--lock-dir",
            "/tmp/locks",
            "--devices",
            "/dev/sda",
        ]);
        assert!(args.is_ok(), "pool import --lock-dir should parse");
    }

    #[test]
    fn cli_parse_pool_import_rejects_no_name() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import"]);
        assert!(args.is_err(), "pool import without pool name should fail");
    }

    #[test]
    fn cli_parse_pool_import_rejects_device_only_positional() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "import", "/dev/sda"]);
        assert!(
            args.is_err(),
            "pool import must not parse a device path as the pool identity"
        );
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
    fn cli_parse_snapshot_create_rejects_backing_dir() {
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
            args.is_err(),
            "snapshot create with backing-dir must be retired"
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
    fn cli_parse_volume_snapshot_uses_shared_snapshot_commands() {
        use clap::Parser;

        for operation in ["create", "destroy", "rollback"] {
            assert!(Cli::try_parse_from([
                "tidefsctl",
                "snapshot",
                operation,
                "mypool/vol@before",
                "--devices",
                "/dev/sda",
            ])
            .is_ok());
        }
        assert!(Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "list",
            "mypool",
            "--devices",
            "/dev/sda",
        ])
        .is_ok());
        assert!(Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "volume",
            "create",
            "mypool/vol@before",
        ])
        .is_err());
    }

    #[test]
    fn cli_parse_snapshot_list_rejects_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "list",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(
            args.is_err(),
            "snapshot list with backing-dir must be retired"
        );
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
    fn cli_parse_snapshot_clone_lifecycle() {
        use clap::Parser;
        for argv in [
            [
                "tidefsctl",
                "snapshot",
                "clone",
                "create",
                "mypool",
                "clone-a",
                "volume-a@snap-a",
            ]
            .as_slice(),
            [
                "tidefsctl",
                "snapshot",
                "clone",
                "delete",
                "mypool",
                "clone-a",
            ]
            .as_slice(),
            [
                "tidefsctl",
                "snapshot",
                "clone",
                "promote",
                "mypool",
                "clone-a",
            ]
            .as_slice(),
        ] {
            let args = Cli::try_parse_from(argv.iter().copied());
            assert!(
                args.is_ok(),
                "snapshot clone lifecycle should parse: {argv:?}"
            );
        }
    }

    #[test]
    fn cli_parse_snapshot_bookmark_lifecycle() {
        use clap::Parser;
        let create = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "bookmark",
            "create",
            "mypool",
            "bm-a",
            "snap-a",
        ]);
        assert!(create.is_ok(), "snapshot bookmark create should parse");

        let delete = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "bookmark",
            "delete",
            "mypool",
            "bm-a",
        ]);
        assert!(delete.is_ok(), "snapshot bookmark delete should parse");
    }

    #[test]
    fn cli_parse_snapshot_holds_and_prune() {
        use clap::Parser;
        for argv in [
            ["tidefsctl", "snapshot", "hold", "mypool", "snap-a"].as_slice(),
            ["tidefsctl", "snapshot", "release", "mypool", "snap-a"].as_slice(),
            ["tidefsctl", "snapshot", "holds", "mypool"].as_slice(),
            ["tidefsctl", "snapshot", "holds", "mypool", "snap-a"].as_slice(),
            [
                "tidefsctl",
                "snapshot",
                "prune",
                "mypool",
                "--keep-latest",
                "2",
            ]
            .as_slice(),
            [
                "tidefsctl",
                "snapshot",
                "prune",
                "mypool",
                "--max-age-generations",
                "24",
            ]
            .as_slice(),
        ] {
            let args = Cli::try_parse_from(argv.iter().copied());
            assert!(
                args.is_ok(),
                "snapshot hold/release/prune command should parse: {argv:?}"
            );
        }
    }

    #[test]
    fn cli_parse_snapshot_destroy_rejects_backing_dir() {
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
            args.is_err(),
            "snapshot destroy with backing-dir must be retired"
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
    fn cli_parse_snapshot_destroy_rejects_short_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "destroy",
            "mysnap",
            "-b",
            "/tmp/pool",
        ]);
        assert!(args.is_err(), "snapshot destroy -b must be retired");
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

    #[test]
    fn cli_parse_snapshot_prune_scheduled_surfaces() {
        use clap::Parser;
        for surface in [
            "policy", "plan", "enable", "disable", "status", "refusals", "results",
        ] {
            let args = Cli::try_parse_from([
                "tidefsctl",
                "snapshot",
                "prune-scheduled",
                surface,
                "mypool",
            ]);
            assert!(
                args.is_ok(),
                "snapshot prune-scheduled {surface} should parse"
            );
        }
    }

    #[test]
    fn cli_parse_snapshot_prune_manual_surface_still_accepts_policy_flags() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "prune",
            "mypool",
            "--keep-latest",
            "2",
        ]);
        assert!(args.is_ok(), "manual snapshot prune should keep parsing");
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn cli_parse_snapshot_receive_live_pool_positional() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "receive",
            "mypool",
            "--input",
            "/tmp/mypool.vfssend1",
        ]);
        assert!(
            args.is_ok(),
            "snapshot receive with positional pool should parse"
        );
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn cli_parse_snapshot_receive_rejects_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "receive",
            "--backing-dir",
            "/tmp/pool",
            "--input",
            "/tmp/mypool.vfssend1",
        ]);
        assert!(
            args.is_err(),
            "snapshot receive backing-dir must be retired"
        );
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn cli_parse_snapshot_receive_rejects_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "snapshot",
            "receive",
            "mypool",
            "--devices",
            "/dev/sda",
            "--input",
            "/tmp/mypool.vfssend1",
        ]);
        assert!(
            args.is_err(),
            "snapshot receive must not accept offline devices"
        );
    }

    #[test]
    #[cfg(feature = "replication-io")]
    fn cli_help_snapshot_receive_is_live_owner_only() {
        #[derive(clap::Parser)]
        struct SnapshotHelpCli {
            #[command(subcommand)]
            cmd: commands::snapshot::SnapshotCommand,
        }

        let receive_help = SnapshotHelpCli::command()
            .find_subcommand_mut("receive")
            .map(|command| render_long_help(command.clone()))
            .expect("snapshot receive help exists");

        assert!(receive_help.contains("--input"));
        assert!(receive_help.contains("POOL"));
        assert!(!receive_help.contains("--devices"));
        assert!(!receive_help.contains("--backing-dir"));
    }

    // -- Device CLI parse tests -------------------------------------------

    #[test]
    fn cli_parse_device_remove_keeps_only_pool_and_device_inputs() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "device", "remove", "mypool", "/dev/sdc"]);
        assert!(
            args.is_ok(),
            "device remove for imported pool should parse without offline store arguments"
        );

        for args in [
            vec![
                "tidefsctl",
                "device",
                "remove",
                "mypool",
                "/dev/sdc",
                "--replication-factor",
                "3",
            ],
            vec![
                "tidefsctl",
                "device",
                "remove",
                "mypool",
                "/dev/sdc",
                "--failure-domain",
                "rack",
            ],
            vec![
                "tidefsctl",
                "device",
                "remove",
                "mypool",
                "/dev/sdc",
                "--force",
            ],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "refused removal must not retain ignored policy inputs"
            );
        }
    }

    #[test]
    fn cli_parse_device_remove_rejects_offline_backing_dirs() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "device",
            "remove",
            "mypool",
            "/dev/sdc",
            "--backing-dir",
            "/var/lib/tidefs/device-sdc",
            "--surviving-dirs",
            "/var/lib/tidefs/device-sdb",
        ]);
        assert!(
            args.is_err(),
            "device remove backing-dir/surviving-dirs must be retired"
        );
    }

    #[test]
    fn cli_parse_device_replace_keeps_only_live_owner_inputs() {
        use clap::Parser;
        let parsed = Cli::try_parse_from([
            "tidefsctl",
            "device",
            "replace",
            "mypool",
            "/dev/sdc",
            "/dev/sdd",
            "--json",
        ]);
        assert!(parsed.is_ok(), "device replace --json should parse");

        for args in [
            vec!["tidefsctl", "device", "replace", "mypool", "/dev/sdc"],
            vec![
                "tidefsctl",
                "device",
                "replace",
                "mypool",
                "/dev/sdc",
                "/dev/sdd",
                "--devices",
                "/dev/sdb",
            ],
            vec![
                "tidefsctl",
                "device",
                "replace",
                "mypool",
                "/dev/sdc",
                "/dev/sdd",
                "--backing-dir",
                "/var/lib/tidefs/pool",
            ],
        ] {
            assert!(
                Cli::try_parse_from(args).is_err(),
                "device replace must not admit offline or incomplete inputs"
            );
        }
    }

    // -- Block CLI parse tests -------------------------------------------

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_attach_named_volume() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "block", "attach", "mypool/vol"]);
        assert!(args.is_ok(), "named volume target should parse");
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_attach_accepts_explicit_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "block",
            "attach",
            "mypool/vol",
            "--devices",
            "/dev/loop0",
            "/dev/loop1",
        ]);
        assert!(args.is_ok(), "explicit Pool devices should parse");
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_attach_rejects_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "block",
            "attach",
            "mypool/vol",
            "--backing-dir",
            "/var/lib/tidefs/mypool",
        ]);
        assert!(args.is_err(), "block attach backing-dir must be retired");
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_attach_rejects_unavailable_io_uring_path() {
        use clap::Parser;
        let args =
            Cli::try_parse_from(["tidefsctl", "block", "attach", "mypool/vol", "--io-uring"]);
        assert!(
            args.is_err(),
            "Pool volume attach must not advertise direct-file io_uring"
        );
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_send_is_removed() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "block", "send", "mypool/vol"]);
        assert!(args.is_err(), "uncanonical block send must not parse");
    }

    #[cfg(feature = "block-volume")]
    #[test]
    fn cli_parse_block_receive_is_removed() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "block", "receive", "mypool/vol"]);
        assert!(args.is_err(), "uncanonical block receive must not parse");
    }

    // -- Kernel CLI parse tests ------------------------------------------

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_kernel_status_default() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "kernel", "status"]);
        assert!(args.is_ok(), "kernel status should parse");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_kernel_status_json_and_control_dev() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "kernel",
            "status",
            "--json",
            "--control-dev",
            "/dev/null",
        ]);
        assert!(
            args.is_ok(),
            "kernel status --json --control-dev should parse"
        );
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_kernel_rejects_missing_subcommand() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "kernel"]);
        assert!(args.is_err(), "kernel requires a subcommand");
    }

    // -- Diagnostic bundle CLI parse tests --------------------------------

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_diag_json() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "diag", "--json"]);
        assert!(args.is_ok(), "diag --json should parse");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_diag_devices_are_offline_input() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "diag",
            "--json",
            "--devices",
            "/dev/sda",
            "/dev/sdb",
        ]);
        assert!(args.is_ok(), "diag --devices should parse as offline input");
    }

    #[cfg(feature = "diagnostics")]
    #[test]
    fn cli_parse_diag_rejects_pool_name_path() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "diag", "tank", "--json"]);
        assert!(
            args.is_err(),
            "diag does not expose a pool-name live-owner diagnostic path yet"
        );
    }

    // -- Dataset CLI parse tests ------------------------------------------

    #[test]
    fn cli_parse_dataset_create_target_with_options() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "create",
            "tank/data",
            "--mountpoint",
            "/srv/data",
            "--property",
            "access.readonly=on",
            "--feature",
            "org.tidefs:compression_zstd",
            "--json",
        ]);
        assert!(
            args.is_ok(),
            "dataset create with target, mountpoint, properties, features, and json should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_create_rejects_legacy_pool_name_shape() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "dataset", "create", "mypool", "data"]);
        assert!(
            args.is_err(),
            "dataset create no longer accepts separate pool and name positionals"
        );
    }

    #[test]
    fn cli_parse_dataset_list_filters() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "list",
            "--pool",
            "mypool",
            "--type",
            "filesystem",
            "--json",
        ]);
        assert!(
            args.is_ok(),
            "dataset list with pool/type filters and json should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_resize_target_size_and_devices() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "resize",
            "tank/vol",
            "--size",
            "1048576",
            "--devices",
            "/dev/vdb",
            "--json",
        ]);
        assert!(
            args.is_ok(),
            "dataset resize with target, exact size, devices, and json should parse"
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
    fn cli_parse_dataset_destroy_target_force_json() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "destroy",
            "tank/data",
            "--force",
            "--json",
        ]);
        assert!(
            args.is_ok(),
            "dataset destroy target with force and json should parse"
        );
    }

    #[test]
    fn cli_parse_dataset_get_set_targets() {
        use clap::Parser;
        let get = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "get",
            "tank/data",
            "access.readonly",
            "--json",
        ]);
        assert!(get.is_ok(), "dataset get target property should parse");

        let set = Cli::try_parse_from([
            "tidefsctl",
            "dataset",
            "set",
            "tank/data",
            "access.readonly=off",
            "--json",
        ]);
        assert!(set.is_ok(), "dataset set target assignment should parse");
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

    #[cfg(feature = "cluster")]
    #[test]
    fn cluster_client_pool_mount_requires_exact_remote_inputs() {
        use clap::Parser;

        let valid = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster-client",
            "--cluster-vfs-rpc-addr",
            "127.0.0.1:7412",
            "--cluster-pool-guid",
            "00112233445566778899aabbccddeeff",
            "--cluster-node-credential",
            "/etc/tidefs/client.credential",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/owner.identity",
        ]);
        assert!(valid.is_ok(), "complete cluster-client mount should parse");

        let missing_pool = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster-client",
            "--cluster-vfs-rpc-addr",
            "127.0.0.1:7412",
            "--cluster-node-credential",
            "/etc/tidefs/client.credential",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/owner.identity",
        ]);
        assert!(
            missing_pool.is_err(),
            "cluster-client mount must require an expected Pool GUID"
        );

        let local_devices = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster-client",
            "--cluster-vfs-rpc-addr",
            "127.0.0.1:7412",
            "--cluster-pool-guid",
            "00112233445566778899aabbccddeeff",
            "--cluster-node-credential",
            "/etc/tidefs/client.credential",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/owner.identity",
            "--devices",
            "/dev/loop0",
        ]);
        assert!(
            local_devices.is_err(),
            "cluster-client mount must conflict with local devices"
        );

        let owner_mode = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster-client",
            "--cluster",
            "--cluster-vfs-rpc-addr",
            "127.0.0.1:7412",
            "--cluster-pool-guid",
            "00112233445566778899aabbccddeeff",
            "--cluster-node-credential",
            "/etc/tidefs/client.credential",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/owner.identity",
        ]);
        assert!(
            owner_mode.is_err(),
            "cluster-client and cluster-owner mount modes must conflict"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_accepts_explicit_identity_surfaces() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster",
            "--cluster-authority-addr",
            "127.0.0.1:7411",
            "--cluster-vfs-rpc-bind",
            "127.0.0.1:7412",
            "--cluster-node-credential",
            "/etc/tidefs/node.credential",
            "--cluster-trusted-authority-identity",
            "/etc/tidefs/authority.identity",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/peer-a.identity",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/peer-b.identity",
        ]);

        assert!(
            args.is_ok(),
            "cluster owner mount should accept repeated trusted peer identities"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_identity_create_requires_separate_paths() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "cluster",
            "identity",
            "create",
            "--node-id",
            "2",
            "--credential",
            "/etc/tidefs/node.credential",
            "--public-identity",
            "/etc/tidefs/node.identity",
        ]);
        assert!(args.is_ok(), "cluster identity creation should parse");

        let missing_public = Cli::try_parse_from([
            "tidefsctl",
            "cluster",
            "identity",
            "create",
            "--node-id",
            "2",
            "--credential",
            "/etc/tidefs/node.credential",
        ]);
        assert!(
            missing_public.is_err(),
            "cluster identity creation must require the public output path"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_requires_vfs_rpc_owner_bind() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster",
            "--cluster-authority-addr",
            "127.0.0.1:7411",
            "--cluster-node-credential",
            "/etc/tidefs/node.credential",
            "--cluster-trusted-authority-identity",
            "/etc/tidefs/authority.identity",
            "--cluster-trusted-vfs-rpc-peer-identity",
            "/etc/tidefs/peer.identity",
        ]);

        assert!(
            args.is_err(),
            "cluster mount must not parse without a Pool-backed VFS_RPC owner bind"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_requires_node_trust_records() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster",
            "--cluster-authority-addr",
            "127.0.0.1:7411",
            "--cluster-vfs-rpc-bind",
            "127.0.0.1:7412",
        ]);
        assert!(
            args.is_err(),
            "cluster mount must require local credential and trusted peer identity paths"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_rejects_retired_ambiguous_node_flags() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster",
            "--cluster-node-id",
            "1",
            "--cluster-node-addr",
            "127.0.0.1:7411",
        ]);

        assert!(
            args.is_err(),
            "ambiguous cluster node flags must stay retired"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_rejects_retired_numeric_authority_flags() {
        use clap::Parser;
        for flag in ["--cluster-owner-node-id", "--cluster-authority-node-id"] {
            let args = Cli::try_parse_from([
                "tidefsctl",
                "pool",
                "mount",
                "testpool",
                "/mnt/tidefs",
                "--cluster",
                "--cluster-authority-addr",
                "127.0.0.1:7411",
                "--cluster-vfs-rpc-bind",
                "127.0.0.1:7412",
                "--cluster-node-credential",
                "/etc/tidefs/node.credential",
                "--cluster-trusted-authority-identity",
                "/etc/tidefs/authority.identity",
                "--cluster-trusted-vfs-rpc-peer-identity",
                "/etc/tidefs/peer.identity",
                flag,
                "2",
            ]);
            assert!(
                args.is_err(),
                "retired numeric authority flag {flag} parsed"
            );
        }
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_pool_mount_rejects_authority_without_cluster_mode() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "mount",
            "testpool",
            "/mnt/tidefs",
            "--cluster-trusted-authority-identity",
            "/etc/tidefs/authority.identity",
        ]);

        assert!(
            args.is_err(),
            "cluster authority flags must not be silently ignored by a local mount"
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
        let args = Cli::try_parse_from(["tidefsctl", "pool", "integrity-check", "mypool"]);
        assert!(
            args.is_ok(),
            "pool integrity-check with pool name should parse"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_rejects_backing_dir() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "mypool",
            "--backing-dir",
            "/tmp/pool",
        ]);
        assert!(
            args.is_err(),
            "pool integrity-check backing-dir must be retired"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_json() {
        use clap::Parser;
        let args =
            Cli::try_parse_from(["tidefsctl", "pool", "integrity-check", "mypool", "--json"]);
        assert!(args.is_ok(), "pool integrity-check --json should parse");
    }

    #[test]
    fn cli_parse_pool_integrity_check_max_records() {
        use clap::Parser;
        let args = Cli::try_parse_from([
            "tidefsctl",
            "pool",
            "integrity-check",
            "mypool",
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
            "mypool",
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
            "mypool",
            "--backing-dir",
            "/tmp/pool",
            "--devices",
            "/dev/sdb",
            "--json",
            "--max-records",
            "1000",
            "--max-bytes",
            "1048576",
        ]);
        assert!(
            args.is_err(),
            "pool integrity-check must reject retired backing-dir even with devices"
        );
    }

    #[test]
    fn cli_parse_pool_integrity_check_rejects_no_pool() {
        use clap::Parser;
        let args = Cli::try_parse_from(["tidefsctl", "pool", "integrity-check"]);
        assert!(
            args.is_err(),
            "pool integrity-check without pool should fail"
        );
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_status_default() {
        use clap::Parser;
        let args = super::Cli::try_parse_from(["tidefsctl", "cluster", "status", "mypool"]);
        assert!(args.is_ok(), "cluster status with pool name should parse");
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_status_json() {
        use clap::Parser;
        let args =
            super::Cli::try_parse_from(["tidefsctl", "cluster", "status", "mypool", "--json"]);
        assert!(args.is_ok(), "cluster status --json should parse");
    }

    #[cfg(feature = "cluster")]
    #[test]
    fn cli_parse_cluster_status_rejects_no_pool() {
        use clap::Parser;
        let args = super::Cli::try_parse_from(["tidefsctl", "cluster", "status"]);
        assert!(
            args.is_err(),
            "cluster status without pool name should fail"
        );
    }

    #[test]
    fn cli_parse_device_status_default() {
        use clap::Parser;
        let args = super::Cli::try_parse_from(["tidefsctl", "device", "status", "mypool"]);
        assert!(args.is_ok(), "device status with pool name should parse");
    }

    #[test]
    fn cli_parse_device_status_json() {
        use clap::Parser;
        let args =
            super::Cli::try_parse_from(["tidefsctl", "device", "status", "mypool", "--json"]);
        assert!(args.is_ok(), "device status --json should parse");
    }

    #[test]
    fn cli_parse_device_status_rejects_no_pool() {
        use clap::Parser;
        let args = super::Cli::try_parse_from(["tidefsctl", "device", "status"]);
        assert!(args.is_err(), "device status without pool name should fail");
    }
}
