//! check-crash-oracle gate for tidefs-xtask.
//!
//! Validates the `tidefs-crash-oracle` crate by running its tests and
//! checking that the model crash report artifact is present and valid.

use std::path::PathBuf;
use std::process::Command;

/// Run the full check-crash-oracle gate.
///
/// 1. Runs `cargo test -p tidefs-crash-oracle`.
/// 2. Loads the model crash report from `validation/artifacts/crash-oracle/model-crash-matrices.json`.
/// 3. Validates the report structure (model matrices, injection matrices, runtime claims).
/// 4. Checks that every required injection point is defined.
pub fn check_crash_oracle_current_workspace() -> Result<(), String> {
    let repo_root = find_repo_root()?;

    // 1. Run crate tests
    let test_status = Command::new("cargo")
        .args(["test", "-p", "tidefs-crash-oracle"])
        .current_dir(&repo_root)
        .status()
        .map_err(|e| format!("cargo test -p tidefs-crash-oracle: {e}"))?;
    if !test_status.success() {
        return Err("cargo test -p tidefs-crash-oracle failed".to_string());
    }

    // 2. Load and validate the artifact
    let artifact_path =
        repo_root.join("validation/artifacts/crash-oracle/model-crash-matrices.json");
    let json_bytes = std::fs::read(&artifact_path)
        .map_err(|e| format!("read {}: {e}", artifact_path.display()))?;

    let report: tidefs_crash_oracle::CrashOracleReport = serde_json::from_slice(&json_bytes)
        .map_err(|e| format!("decode {}: {e}", artifact_path.display()))?;

    report
        .validate()
        .map_err(|e| format!("crash report validation failed: {e}"))?;

    // 3. Check injection matrix requirements
    let injection_matrix = report
        .injection_matrices
        .iter()
        .find(|m| m.id == tidefs_crash_oracle::LOCAL_VFS_INJECTION_MATRIX_ID)
        .ok_or_else(|| {
            format!(
                "missing injection matrix {}",
                tidefs_crash_oracle::LOCAL_VFS_INJECTION_MATRIX_ID
            )
        })?;

    let required_injection_points = [
        "vfs.after_write.before_fsync",
        "vfs.after_fsync.before_unmount",
        "vfs.during_fsync",
        "vfs.during_directory_update",
        "vfs.during_inode_attribute_update",
    ];

    for required_id in &required_injection_points {
        if !injection_matrix
            .injection_points
            .iter()
            .any(|case| case.id == *required_id)
        {
            return Err(format!("missing required injection point: {required_id}"));
        }
    }

    // 4. Check that no injection point claims runtime evidence
    for case in &injection_matrix.injection_points {
        if case.has_runtime_evidence {
            return Err(format!(
                "injection point {} incorrectly claims runtime evidence in definition matrix",
                case.id
            ));
        }
    }

    println!("check-crash-oracle: PASS");
    println!("  model matrices: {}", report.matrices.len());
    println!("  model cases: {}", report.case_count());
    println!("  injection matrices: {}", report.injection_matrices.len());
    println!("  injection points: {}", report.injection_case_count());
    println!("  runtime claims: {}", report.runtime_claims.len());

    Ok(())
}

fn find_repo_root() -> Result<PathBuf, String> {
    let output = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| format!("git rev-parse: {e}"))?;
    if !output.status.success() {
        return Err("git rev-parse --show-toplevel failed".to_string());
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}
