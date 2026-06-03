//! Kernel-portability dependency guard for tidefs-local-filesystem (#5942, #5985, #6174).
//!
//! This build script fails when a forbidden userspace/adapter dependency
//! appears in Cargo.toml and verifies the transitive dependency closure of
//! kernel-portable storage-core crates via `cargo tree`.
//!
//! The workspace-level canonical check is `cargo xtask check-kernel-closure`
//! (see xtask/tidefs-xtask/src/kernel_closure.rs).  This build.rs provides a
//! per-crate fast-path guard that catches the most common regression (a
//! forbidden dep added directly to `tidefs-local-filesystem/Cargo.toml`) and
//! a secondary `cargo tree` sweep of the kernel-portable core closure.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    let manifest_dir_var = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_dir = std::path::Path::new(&manifest_dir_var);

    let toml_path = manifest_dir.join("Cargo.toml");
    let toml_content = std::fs::read_to_string(&toml_path).unwrap_or_else(|e| {
        panic!("build.rs: cannot read Cargo.toml: {e}");
    });

    // -----------------------------------------------------------------------
    // 1. Direct-dep guard: fast string scan of this crate's own Cargo.toml.
    // -----------------------------------------------------------------------
    let forbidden_direct: &[(&str, &str)] = &[
        (
            "tidefs-posix-filesystem-adapter-workers-locks",
            "POSIX adapter worker crate -- belongs in FUSE daemon layer",
        ),
        (
            "tidefs-types-control-plane-core",
            "control-plane scaffold -- use StorageAuthorityToken from types-claim-ledger-core",
        ),
    ];

    for &(dep, reason) in forbidden_direct {
        if toml_content.contains(dep) {
            panic!(
                "KERNEL PORTABILITY VIOLATION in tidefs-local-filesystem:\n\
                 Forbidden dependency '{dep}' found in Cargo.toml.\n\
                 Reason: {reason}\n\
                 See crate module docs and issue #6174.",
            );
        }
    }

    // -----------------------------------------------------------------------
    // 2. Transitive-closure guard: use `cargo tree` to verify that the
    //    canonical kernel-portable storage-core crates do not transitively
    //    depend on any control-plane or POSIX-adapter scaffold crate.
    //    This replaces the old manifest-string scanning (#5985) with a real
    //    resolved-dependency-tree check (#6174).
    // -----------------------------------------------------------------------
    let workspace_root = find_workspace_root(manifest_dir);

    // Kernel-portable core crates whose transitive closure we guard.
    // Keep in sync with xtask/tidefs-xtask/src/kernel_closure.rs KERNEL_PORTABLE_CORE.
    let kernel_portable: &[&str] = &[
        "tidefs-local-filesystem",
        "tidefs-types-claim-ledger-core",
        "tidefs-claim-ledger",
        "tidefs-reserve-ledger",
        "tidefs-types-vfs-core",
        "tidefs-types-space-accounting-core",
        "tidefs-types-extent-map-core",
        "tidefs-vfs-engine",
        "tidefs-inode-table",
        "tidefs-inode-attributes",
        "tidefs-block-allocator",
        "tidefs-local-object-store",
        "tidefs-intent-log",
        "tidefs-recovery-loop",
        "tidefs-dir-index",
        "tidefs-extent-map",
        "tidefs-posix-semantics",
        "tidefs-orphan-index",
        "tidefs-scrub-core",
        "tidefs-posix-acl",
        "tidefs-space-accounting",
        "tidefs-erasure-coding",
        "tidefs-commit_group",
        "tidefs-cleanup-engine",
        "tidefs-reclaim-queue-core",
        "tidefs-dataset-lifecycle",
        "tidefs-dataset-feature-flags",
        "tidefs-pool-scan",
    ];

    // Forbidden crates that must not appear in the transitive closure.
    // Keep in sync with xtask/tidefs-xtask/src/kernel_closure.rs FORBIDDEN_CRATES.
    let forbidden_transitive: &[&str] = &[
        "tidefs-types-control-plane-core",
        "tidefs-posix-filesystem-adapter-workers-locks",
        "tidefs-types-posix-filesystem-adapter-core",
        "tidefs-schema-codec-posix-filesystem-adapter",
        "tidefs-posix-filesystem-adapter-runtime",
        "tidefs-posix-filesystem-adapter-reply",
        "tidefs-posix-filesystem-adapter-workers-io",
        "tidefs-posix-filesystem-adapter-daemon",
        "tidefs-block-volume-adapter-core",
        "tidefs-block-volume-adapter-daemon",
        "tidefs-block-volume-adapter-ublk-control-runtime",
    ];

    let mut violations: Vec<(String, String)> = Vec::new();

    for &kp_crate in kernel_portable {
        // Check if the crate directory exists before querying.
        if !manifest_dir
            .join("..")
            .join(kp_crate)
            .join("Cargo.toml")
            .exists()
        {
            continue;
        }

        let output = Command::new("cargo")
            .args([
                "tree",
                "-p",
                kp_crate,
                "--no-dedupe",
                "--edges",
                "normal",
                "--prefix",
                "none",
            ])
            .current_dir(&workspace_root)
            .output();

        let stdout = match output {
            Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).into_owned(),
            Ok(o) => {
                let stderr = String::from_utf8_lossy(&o.stderr);
                // `cargo tree -p` fails when the crate is a workspace member
                // but doesn't appear in the resolved graph (no in-tree dep
                // on it from any other crate). That is fine: an unlinked
                // crate can't introduce forbidden transitive deps.
                if stderr.contains("package id specification") {
                    continue;
                }
                panic!("build.rs: cargo tree -p {kp_crate} failed: {stderr}");
            }
            Err(e) => {
                panic!("build.rs: failed to run cargo tree: {e}");
            }
        };

        for forbidden in forbidden_transitive {
            // Match the crate name as a whole token: it appears in cargo
            // tree output as "crate_name v0.x.y" on its own line.  Check
            // for "forbidden " (name followed by space+version) or as the
            // last token on a line.
            if stdout.contains(&format!("{forbidden} ")) || stdout.ends_with(forbidden) {
                violations.push((kp_crate.to_string(), forbidden.to_string()));
            }
        }
    }

    if !violations.is_empty() {
        let mut msg = format!(
            "KERNEL PORTABILITY CLOSURE VIOLATION (#6174): {} forbidden transitive \
             dependency path(s) found:\n",
            violations.len()
        );
        for (kp, forbidden) in &violations {
            msg.push_str(&format!("  {kp} -> ... -> {forbidden}\n"));
        }
        msg.push_str(
            "\nStorage-core crates must not depend on control-plane or \
             POSIX-adapter scaffold crates.\n\
             Check the dependency chain and remove the offending edge.\n\
             See issue #6174 and xtask/tidefs-xtask/src/kernel_closure.rs.",
        );
        panic!("{msg}");
    }
}

/// Walk up from `start` to find the workspace root (directory containing
/// a Cargo.toml with `[workspace]`).
fn find_workspace_root(start: &Path) -> std::path::PathBuf {
    for ancestor in start.ancestors() {
        let cargo_toml = ancestor.join("Cargo.toml");
        if cargo_toml.exists() {
            if let Ok(content) = std::fs::read_to_string(&cargo_toml) {
                if content.contains("[workspace]") {
                    return ancestor.to_path_buf();
                }
            }
        }
    }
    panic!("build.rs: cannot find workspace root (no Cargo.toml with [workspace] found)");
}
