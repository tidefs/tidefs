// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct PlatformCheckError {
    missing: Vec<String>,
}

impl fmt::Display for PlatformCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "platform scaffolding check failed:")?;
        for item in &self.missing {
            writeln!(f, "- {item}")?;
        }
        Ok(())
    }
}

pub fn check_current_workspace() -> Result<(), PlatformCheckError> {
    let root = find_workspace_root().ok_or_else(|| PlatformCheckError {
        missing: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut missing = Vec::new();

    for rel in [
        "flake.nix",
        "nix/tidefs-validation.sh",
        "nix/tidefs-qemu-direct.sh",
        "nix/tidefs-rdma-probe.sh",
        "docs/GITHUB_CI.md",
        "docs/XFSTESTS_DISPATCH_CONTRACT.md",
        "docs/TRANSPORT_CLUSTER_AUTHORITY.md",
    ] {
        check_required_file(&root, rel, &mut missing);
    }

    check_source_markers(
        &root,
        "flake.nix",
        &[
            "rust-bin.fromRustupToolchainFile ./rust-toolchain.toml",
            "rdma-core",
            "qemuSmoke",
            "tidefs-qemu-smoke",
            "tidefs-rdma-probe",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/TRANSPORT_CLUSTER_AUTHORITY.md",
        &[
            "Transport owns session-local admission",
            "RDMA hardware validation and partition recovery",
            "product claims require runtime",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "nix/tidefs-rdma-probe.sh",
        &["transport_session_0_fallback", "rdma_rxe", "siw"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/GITHUB_CI.md",
        &["TIDEFS_SELF_HOSTED_READY", "QEMU Smoke", "xfstests", "RDMA"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/XFSTESTS_DISPATCH_CONTRACT.md",
        &[
            "Workflow file",
            ".github/workflows/xfstests.yml",
            ".#fuse-xfstests-validation",
            "kmod-smoke",
            "k7-vfs",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("platform scaffolding ok: current Nix proof, outside-sandbox QEMU direct, and optional RDMA probe surfaces are present");
        Ok(())
    } else {
        Err(PlatformCheckError { missing })
    }
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let manifest = current.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&manifest) {
            if text.contains("[workspace]") {
                return Some(current);
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

fn check_required_file(root: &Path, rel: &str, missing: &mut Vec<String>) {
    if !root.join(rel).is_file() {
        missing.push(format!("missing required file `{rel}`"));
    }
}

fn check_source_markers(root: &Path, rel: &str, markers: &[&str], missing: &mut Vec<String>) {
    let path = root.join(rel);
    let Ok(text) = fs::read_to_string(&path) else {
        missing.push(format!("could not read `{rel}`"));
        return;
    };
    for marker in markers {
        if !text.contains(marker) {
            missing.push(format!("`{rel}` missing marker `{marker}`"));
        }
    }
}
