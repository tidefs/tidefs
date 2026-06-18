// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Collect a QEMU pin manifest for reproducible validation runs.
//!
//! The `collect-qemu-pin-manifest` subcommand gathers kernel, initrd, disk
//! image, Nix flake.lock, and rebuild recipe into a single
//! [`QemuPinManifest`] JSON artifact that makes a QEMU validation run
//! reproducible.

use std::path::PathBuf;
use std::process;

/// Print usage for the collect-qemu-pin-manifest subcommand.
pub fn print_usage() {
    eprintln!("usage: tidefs-xtask collect-qemu-pin-manifest \\");
    eprintln!("         --validation-id ID \\");
    eprintln!("         --kernel PATH \\");
    eprintln!("         --initrd PATH \\");
    eprintln!("         [--disk-image PATH] \\");
    eprintln!("         --flake-lock PATH \\");
    eprintln!("         --rebuild-recipe CMD \\");
    eprintln!("         --output PATH \\");
    eprintln!("         [--commit SHA] \\");
    eprintln!("         [--nix-derivation PATH]...");
}

/// Run the collect-qemu-pin-manifest subcommand.
///
/// Parses required and optional arguments, collects artifact hashes from
/// on-disk files, reads the flake.lock, and writes the pin manifest JSON.
pub fn run_collect(mut args: impl Iterator<Item = String>) {
    let mut validation_id: Option<String> = None;
    let mut commit: Option<String> = None;
    let mut kernel_path: Option<PathBuf> = None;
    let mut initrd_path: Option<PathBuf> = None;
    let mut disk_image_path: Option<PathBuf> = None;
    let mut flake_lock_path: Option<PathBuf> = None;
    let mut rebuild_recipe: Option<String> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut nix_derivations: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" | "help" => {
                print_usage();
                return;
            }
            "--validation-id" => {
                validation_id = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--validation-id requires an identifier");
                    process::exit(2);
                }));
            }
            "--commit" => {
                commit = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--commit requires a SHA");
                    process::exit(2);
                }));
            }
            "--kernel" => {
                kernel_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--kernel requires a path");
                    process::exit(2);
                })));
            }
            "--initrd" => {
                initrd_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--initrd requires a path");
                    process::exit(2);
                })));
            }
            "--disk-image" => {
                disk_image_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--disk-image requires a path");
                    process::exit(2);
                })));
            }
            "--flake-lock" => {
                flake_lock_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--flake-lock requires a path");
                    process::exit(2);
                })));
            }
            "--rebuild-recipe" => {
                rebuild_recipe = Some(args.next().unwrap_or_else(|| {
                    eprintln!("--rebuild-recipe requires a command string");
                    process::exit(2);
                }));
            }
            "--output" => {
                output_path = Some(PathBuf::from(args.next().unwrap_or_else(|| {
                    eprintln!("--output requires a path");
                    process::exit(2);
                })));
            }
            "--nix-derivation" => {
                nix_derivations.push(args.next().unwrap_or_else(|| {
                    eprintln!("--nix-derivation requires a path");
                    process::exit(2);
                }));
            }
            other => {
                eprintln!("unknown option: {other}");
                print_usage();
                process::exit(2);
            }
        }
    }

    // Validate required arguments.
    let validation_id = validation_id.unwrap_or_else(|| {
        eprintln!("--validation-id is required");
        print_usage();
        process::exit(2);
    });
    let kernel_path = kernel_path.unwrap_or_else(|| {
        eprintln!("--kernel is required");
        print_usage();
        process::exit(2);
    });
    let initrd_path = initrd_path.unwrap_or_else(|| {
        eprintln!("--initrd is required");
        print_usage();
        process::exit(2);
    });
    let flake_lock_path = flake_lock_path.unwrap_or_else(|| {
        eprintln!("--flake-lock is required");
        print_usage();
        process::exit(2);
    });
    let rebuild_recipe = rebuild_recipe.unwrap_or_else(|| {
        eprintln!("--rebuild-recipe is required");
        print_usage();
        process::exit(2);
    });
    let output_path = output_path.unwrap_or_else(|| {
        eprintln!("--output is required");
        print_usage();
        process::exit(2);
    });

    let commit = commit.unwrap_or_else(|| {
        // Try to detect commit from git.
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| "unknown".to_string())
    });

    let manifest = tidefs_validation::qemu_pin_manifest::QemuPinManifest::collect(
        tidefs_validation::qemu_pin_manifest::QemuPinManifestCollect {
            validation_id: &validation_id,
            commit: &commit,
            kernel_path: &kernel_path,
            initrd_path: &initrd_path,
            disk_image_path: disk_image_path.as_deref(),
            flake_lock_path: &flake_lock_path,
            rebuild_recipe: &rebuild_recipe,
            nix_store_derivations: &nix_derivations,
        },
    )
    .unwrap_or_else(|| {
        eprintln!(
            "ERROR: failed to collect pin manifest. Check that kernel ({}) and \
             initrd ({}) exist, and that flake.lock ({}) is valid JSON.",
            kernel_path.display(),
            initrd_path.display(),
            flake_lock_path.display()
        );
        process::exit(1);
    });

    // Write the manifest.
    let json = serde_json::to_string_pretty(&manifest).unwrap_or_else(|e| {
        eprintln!("ERROR: failed to serialize pin manifest: {e}");
        process::exit(1);
    });

    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).unwrap_or_else(|e| {
            eprintln!(
                "ERROR: cannot create output directory {}: {e}",
                parent.display()
            );
            process::exit(1);
        });
    }

    std::fs::write(&output_path, &json).unwrap_or_else(|e| {
        eprintln!(
            "ERROR: cannot write pin manifest to {}: {e}",
            output_path.display()
        );
        process::exit(1);
    });

    let fp = manifest.nix_inputs_fingerprint();
    println!(
        "QEMU pin manifest collected: {}  kernel_sha256={}  initrd_sha256={}  nix_inputs={}",
        output_path.display(),
        &manifest.kernel.sha256[..16],
        &manifest.initrd.sha256[..16],
        &fp[..fp.len().min(64)]
    );
}
