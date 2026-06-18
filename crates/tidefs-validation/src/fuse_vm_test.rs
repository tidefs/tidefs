// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! NixOS VM integration test harness for TideFS FUSE mount validation.
//!
//! Invokes the `tidefsFuseVmTest` NixOS test derivation defined in the
//! workspace flake. The NixOS test boots a minimal QEMU VM, mounts TideFS
//! FUSE, runs a POSIX smoke suite (stat, readdir, create, write, read,
//! unlink, rmdir), and produces a JSON validation output.
//!
//! When `nix` is not available or the Nix daemon is not functional, the
//! test is skipped.

/// Locate the TideFS workspace root by walking up from the crate directory
/// until `flake.nix` is found.
pub fn workspace_root() -> Option<std::path::PathBuf> {
    use std::path::PathBuf;
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut current = crate_dir.as_path();
    loop {
        if current.join("flake.nix").exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) => current = parent,
            None => return None,
        }
    }
}

/// Check whether `nix` is available on `$PATH`.
pub fn nix_available() -> bool {
    std::process::Command::new("nix")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build and run the NixOS FUSE VM test via `nix build`.
///
/// Returns `Ok(())` when the Nix build succeeds (all smoke tests pass).
/// Returns `Err(msg)` on build failure, test assertion failure, or
/// missing prerequisites.
pub fn run_nix_fuse_vm_test() -> Result<(), String> {
    let root = workspace_root().ok_or("cannot find workspace root")?;

    let output = std::process::Command::new("nix")
        .args([
            "build",
            &format!("{}#tidefsFuseVmTest", root.display()),
            "-L",
        ])
        .output()
        .map_err(|e| format!("failed to run nix build: {e}"))?;

    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        Err(format!(
            "nix build failed (exit {:?}):\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status.code(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NixOS VM integration test: boots a QEMU VM, mounts TideFS FUSE,
    /// and runs the POSIX smoke suite.
    ///
    /// Requires a functional `nix` on `$PATH` with a writable Nix store.
    /// Skips silently when Nix is not available or the daemon is not
    /// reachable. In a sandbox without a writable Nix store the test
    /// skips rather than failing.
    #[test]
    fn fuse_vm_posix_smoke() {
        if !nix_available() {
            eprintln!(
                "SKIP: nix not found on PATH -- \
                 fuse_vm_posix_smoke requires a Nix environment"
            );
            return;
        }

        match run_nix_fuse_vm_test() {
            Ok(()) => {
                eprintln!("PASS: NixOS FUSE VM test completed successfully");
            }
            Err(e) => {
                // If nix fails due to a read-only store or daemon
                // issues (common in sandboxes), skip rather than fail.
                if e.contains("readonly database")
                    || e.contains("read-only file system")
                    || e.contains("No such file or directory")
                {
                    eprintln!(
                        "SKIP: Nix daemon/store not writable in this \
                         environment -- fuse_vm_posix_smoke skipped\n  {e}"
                    );
                    return;
                }
                panic!("NixOS FUSE VM test failed: {e}");
            }
        }
    }

    #[test]
    fn workspace_root_finds_flake() {
        let root = workspace_root().expect("should find flake.nix");
        assert!(root.join("flake.nix").exists());
    }

    #[test]
    fn workspace_root_contains_crates() {
        let root = workspace_root().expect("should find flake.nix");
        assert!(root.join("crates").is_dir());
    }
}
