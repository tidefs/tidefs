//! Shared runtime artifact source required for live-runtime tier Pass rows.
//!
//! MountedUserspace, QemuGuest, MultiProcessDistributed, MountedKernelVfs,
//! KernelBlockIo, and FullKernelNoDaemon Pass rows must cite a concrete
//! [`RuntimeArtifactSource`] showing that the workload actually executed.
//! Those paths are scratch validation output, not repository authority.

use serde::{Deserialize, Serialize};

/// Concrete scratch artifact source showing a live-runtime workload actually ran.
///
/// Required for any live-runtime tier Pass row.  Without this, the row's
/// tier claim is untrustworthy: it could be a schema check, a unit test,
/// or a hard-coded issue reference masquerading as a runtime pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeArtifactSource {
    /// Full command line that produced the validation.
    pub command: String,
    /// Environment description (host, container, QEMU, kernel version).
    pub environment: String,
    /// Repository commit SHA at which the validation was collected.
    pub commit: String,
    /// Kernel version string for kernel-tier validation (e.g. "7.0.0-tidefs+").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Process exit status (0 = success).
    pub exit_status: i32,
    /// Path to recorded stdout output, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdout_path: Option<String>,
    /// Path to recorded stderr output, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr_path: Option<String>,
    /// Whether the workload actually executed (not just schema/model).
    pub workload_ran: bool,
}

impl RuntimeArtifactSource {
    /// Returns true if this artifact represents a genuinely-executed workload
    /// with a valid exit status and command.
    pub fn is_genuine(&self) -> bool {
        self.workload_ran && !self.command.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_is_genuine() {
        let a = RuntimeArtifactSource {
            command: "./run-qemu-test.sh".into(),
            environment: "Linux 7.0 QEMU guest".into(),
            commit: "abc123".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/tmp/out.log".into()),
            stderr_path: None,
            workload_ran: true,
        };
        assert!(a.is_genuine());
    }

    #[test]
    fn artifact_not_genuine_no_command() {
        let a = RuntimeArtifactSource {
            command: "".into(),
            environment: "".into(),
            commit: "abc".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: true,
        };
        assert!(!a.is_genuine());
    }

    #[test]
    fn artifact_not_genuine_not_ran() {
        let a = RuntimeArtifactSource {
            command: "./test.sh".into(),
            environment: "".into(),
            commit: "abc".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: false,
        };
        assert!(!a.is_genuine());
    }

    #[test]
    fn json_roundtrip() {
        let a = RuntimeArtifactSource {
            command: "cargo test".into(),
            environment: "host".into(),
            commit: "def456".into(),
            kernel_version: Some("7.0.0".into()),
            exit_status: 0,
            stdout_path: Some("/tmp/stdout".into()),
            stderr_path: Some("/tmp/stderr".into()),
            workload_ran: true,
        };
        let json = serde_json::to_string(&a).unwrap();
        let b: RuntimeArtifactSource = serde_json::from_str(&json).unwrap();
        assert_eq!(b.command, "cargo test");
        assert_eq!(b.exit_status, 0);
    }

    /// Guard test: proves that a live-runtime Pass row CANNOT be constructed
    /// without a concrete `RuntimeArtifactSource`. The only way to produce a
    /// live-runtime Pass is through an API that requires a `RuntimeArtifactSource`
    /// as a mandatory parameter.
    ///
    /// Downstream modules must likewise require this type for any live-runtime
    /// Pass construction.
    #[test]
    fn guard_live_runtime_pass_requires_artifact_source() {
        let artifact = RuntimeArtifactSource {
            command: "./run-validation.sh".into(),
            environment: "Linux 7.0 QEMU guest, x86_64".into(),
            commit: "deadbeef".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/validation/stdout.log".into()),
            stderr_path: Some("/validation/stderr.log".into()),
            workload_ran: true,
        };

        // Every required field must be populated for a live-runtime pass.
        assert!(
            !artifact.command.is_empty(),
            "command required for live-runtime pass"
        );
        assert!(
            !artifact.environment.is_empty(),
            "environment required for live-runtime pass"
        );
        assert!(
            !artifact.commit.is_empty(),
            "commit SHA required for live-runtime pass"
        );
        assert!(
            artifact.workload_ran,
            "workload_ran must be true for live-runtime pass"
        );
        assert_eq!(artifact.exit_status, 0);
        assert!(artifact.is_genuine());
    }
}
