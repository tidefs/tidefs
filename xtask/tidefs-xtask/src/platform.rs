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
        "docs/NIX_DEVELOPMENT_AND_VALIDATION.md",
        "docs/VALIDATION.md",
        "docs/RDMA_TRANSPORT_POSITION.md",
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
        "docs/RDMA_TRANSPORT_POSITION.md",
        &[
            "cut.linux_baseline.rdma_required_fastpath.x0",
            "transport_session_0",
            "TCP-class transport remains the baseline fallback",
            "rdma_rxe",
            "siw",
        ],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/VALIDATION.md",
        &["ephemeral", "/root/ai/tmp/tidefs-validation", "QEMU"],
        &mut missing,
    );
    check_source_markers(
        &root,
        "docs/NIX_DEVELOPMENT_AND_VALIDATION.md",
        &[
            "nix develop",
            "nix run .#validate",
            "CARGO_TARGET_DIR",
            "/root/ai/tmp/tidefs-validation",
            "nix run .#qemu-direct",
            "TIDEFS_QEMU_KERNEL",
            "nix run .#rdma-probe",
            "TIDEFS_RDMA_ALLOW_MUTATION=1",
            "environment.env",
        ],
        &mut missing,
    );

    if missing.is_empty() {
        println!("platform scaffolding ok: current Nix validation, outside-sandbox QEMU direct, and optional RDMA probe surfaces are present");
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
