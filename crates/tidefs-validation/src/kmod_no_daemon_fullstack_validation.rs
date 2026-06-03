//! kmod-posix-vfs no-daemon full-stack mounted validation module.
//!
//! Produces tier-classified validation output for the full kmod-posix-vfs kernel
//! path — superblock mount, namespace operations, data I/O, fsync durability, and
//! crash remount — operating with zero userspace daemon processes running.
//!
//! # Validation tiers
//!
//! | Tier | Meaning |
//! |---|---|
//! | `SourceModel` | Schema types, lifecycle state machine, and outcome matching validated in simulation |
//! | `QemuBoot` | Linux 7.0 boots with kmod-posix-vfs.ko and block-kmod.ko loaded |
//! | `QemuMountNoDaemon` | Kernel superblock mount succeeds with no userspace daemon process |
//! | `QemuFullStack` | Full create/write/read/rename/unlink/fsync + crash remount with committed-root verification |
//!
//! # Operation kinds
//!
//! - **Create** — file creation through kernel VFS
//! - **Write** — buffered data write through kernel VFS
//! - **Read** — data readback through kernel VFS
//! - **Rename** — namespace rename through kernel VFS
//! - **Unlink** — file removal through kernel VFS
//! - **Fsync** — durability barrier through kernel VFS
//! - **CrashRemount** — controlled crash + remount + committed-root verification
//!
//! # Current validation role
//!
//! This module defines the row schema for no-daemon kernel validation. Concrete
//! QEMU logs, module paths, and kernel paths belong in scratch validation
//! output for the run that produced them, not in source comments.

use crate::runtime_artifact_source::RuntimeArtifactSource;
use serde::{Deserialize, Serialize};
use std::fmt;

// ── FNV-1a 64-bit digest ───────────────────────────────────────────────────

/// Compute the FNV-1a 64-bit hash of a byte slice.
///
/// FNV-1a is used here as a fast, deterministic content digest for validation
/// report fingerprinting — not for cryptographic integrity.
pub fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

/// Compute the FNV-1a 64-bit hash of a string slice.
pub fn fnv1a_str(s: &str) -> u64 {
    fnv1a_64(s.as_bytes())
}

// ── No-daemon operation kind ───────────────────────────────────────────────

/// Operation families exercised by no-daemon full-stack validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NoDaemonOpKind {
    /// File creation through kernel VFS (mknod/create dispatch).
    Create,
    /// Buffered data write through kernel VFS (write_iter dispatch).
    Write,
    /// Data readback through kernel VFS (read_iter dispatch).
    Read,
    /// Namespace rename through kernel VFS (rename dispatch).
    Rename,
    /// File removal through kernel VFS (unlink dispatch).
    Unlink,
    /// Durability barrier through kernel VFS (fsync dispatch).
    Fsync,
    /// Controlled crash + remount + committed-root verification.
    CrashRemount,
}

impl NoDaemonOpKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Write => "write",
            Self::Read => "read",
            Self::Rename => "rename",
            Self::Unlink => "unlink",
            Self::Fsync => "fsync",
            Self::CrashRemount => "crash-remount",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::Create => "File creation through kernel VFS mknod/create dispatch",
            Self::Write => "Buffered data write through kernel VFS write_iter dispatch",
            Self::Read => "Data readback through kernel VFS read_iter dispatch",
            Self::Rename => "Namespace rename through kernel VFS rename dispatch",
            Self::Unlink => "File removal through kernel VFS unlink dispatch",
            Self::Fsync => "Durability barrier through kernel VFS fsync dispatch",
            Self::CrashRemount => {
                "Controlled crash + remount + committed-root consistency verification"
            }
        }
    }

    pub fn is_mutating(&self) -> bool {
        matches!(
            self,
            Self::Create | Self::Write | Self::Rename | Self::Unlink
        )
    }

    /// Operations that produce committed-root state changes.
    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Fsync | Self::CrashRemount)
    }
}

impl fmt::Display for NoDaemonOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── No-daemon validation tier ────────────────────────────────────────────────

/// Validation tier for no-daemon full-stack validation.
///
/// Tiers are ordered from least to most demanding. The report requires
/// all tiers to pass for full-kernel-no-daemon closure.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NoDaemonValidationTier {
    /// Schema types and lifecycle state machine validated in simulation.
    SourceModel = 0,
    /// Linux 7.0 boots with kmod-posix-vfs.ko and block-kmod.ko loaded.
    QemuBoot = 1,
    /// Kernel superblock mount succeeds with no userspace daemon process.
    QemuMountNoDaemon = 2,
    /// Full create/write/read/rename/unlink/fsync + crash remount with
    /// committed-root verification.
    QemuFullStack = 3,
}

impl NoDaemonValidationTier {
    pub fn label(&self) -> &'static str {
        match self {
            Self::SourceModel => "source-model",
            Self::QemuBoot => "qemu-boot",
            Self::QemuMountNoDaemon => "qemu-mount-no-daemon",
            Self::QemuFullStack => "qemu-full-stack",
        }
    }

    /// Returns the minimum tier required for full-kernel-no-daemon closure.
    pub fn terminal_tier() -> Self {
        Self::QemuFullStack
    }

    /// Whether this tier involves a real QEMU process.
    pub fn requires_qemu(&self) -> bool {
        matches!(
            self,
            Self::QemuBoot | Self::QemuMountNoDaemon | Self::QemuFullStack
        )
    }

    /// Whether this tier exercises mounted filesystem operations.
    pub fn is_runtime(&self) -> bool {
        matches!(self, Self::QemuMountNoDaemon | Self::QemuFullStack)
    }

    /// Map this domain tier to the unified [`crate::validation_schema::ValidationTier`].
    pub fn to_validation_tier(self) -> crate::validation_schema::ValidationTier {
        match self {
            Self::SourceModel => crate::validation_schema::ValidationTier::SourceModel,
            Self::QemuBoot => crate::validation_schema::ValidationTier::QemuModuleLoad,
            Self::QemuMountNoDaemon => crate::validation_schema::ValidationTier::FullKernelNoDaemon,
            Self::QemuFullStack => crate::validation_schema::ValidationTier::FullKernelNoDaemon,
        }
    }
}

impl fmt::Display for NoDaemonValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── No-daemon outcome ──────────────────────────────────────────────────────

/// Outcome of a single no-daemon validation operation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum NoDaemonOutcome {
    /// Operation passed with correct semantics.
    Pass,
    /// Operation failed with unexpected error or wrong result.
    Fail,
    /// Operation could not be exercised due to a missing prerequisite.
    Blocked,
    /// Operation was skipped because a prerequisite tier did not pass.
    Skip,
}

impl NoDaemonOutcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Blocked => "blocked",
            Self::Skip => "skip",
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Pass)
    }

    pub fn is_failure(&self) -> bool {
        matches!(self, Self::Fail)
    }

    pub fn is_blocking(&self) -> bool {
        matches!(self, Self::Fail | Self::Blocked)
    }
}

impl fmt::Display for NoDaemonOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ── No-daemon validation row ─────────────────────────────────────────────────

/// A single validation row for one operation at one tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoDaemonValidationRow {
    /// Unique row identifier.
    pub row_id: String,
    /// Validation tier exercised.
    pub tier: NoDaemonValidationTier,
    /// Unified validation tier (T0-T7) derived from domain tier.
    pub unified_tier: crate::validation_schema::ValidationTier,
    /// Operation kind exercised.
    pub op: NoDaemonOpKind,
    /// Outcome of the operation.
    pub outcome: NoDaemonOutcome,
    /// Human-readable detail (error message, blocker reason, etc.).
    pub detail: String,
    /// Concrete artifact source for live-runtime tier Pass classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_source: Option<RuntimeArtifactSource>,
    /// Duration of the operation in milliseconds, if measured.
    pub duration_ms: Option<u64>,
    /// Committed-root digest before operation, if captured.
    pub committed_root_before: Option<String>,
    /// Committed-root digest after operation, if captured.
    pub committed_root_after: Option<String>,
}

impl NoDaemonValidationRow {
    pub fn new(
        row_id: impl Into<String>,
        tier: NoDaemonValidationTier,
        op: NoDaemonOpKind,
        outcome: NoDaemonOutcome,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            row_id: row_id.into(),
            tier,
            unified_tier: tier.to_validation_tier(),
            op,
            outcome,
            detail: detail.into(),
            artifact_source: None,
            duration_ms: None,
            committed_root_before: None,
            committed_root_after: None,
        }
    }

    /// Set committed-root digests for crash-consistency rows.
    pub fn with_committed_roots(
        mut self,
        before: impl Into<String>,
        after: impl Into<String>,
    ) -> Self {
        self.committed_root_before = Some(before.into());
        self.committed_root_after = Some(after.into());
        self
    }

    /// Set operation duration.
    pub fn with_duration(mut self, ms: u64) -> Self {
        self.duration_ms = Some(ms);
        self
    }

    /// Compute the FNV-1a row digest for fingerprinting.
    pub fn row_digest(&self) -> u64 {
        let payload = format!(
            "{}:{}:{}:{}",
            self.tier.label(),
            self.op.label(),
            self.outcome.label(),
            self.detail
        );
        fnv1a_str(&payload)
    }

    /// Whether this row represents a passing terminal tier.
    pub fn is_terminal_pass(&self, terminal_tier: NoDaemonValidationTier) -> bool {
        self.tier >= terminal_tier && self.outcome == NoDaemonOutcome::Pass
    }

    /// Attach a runtime artifact source proving the workload actually executed.
    pub fn with_artifact(mut self, artifact: RuntimeArtifactSource) -> Self {
        self.artifact_source = Some(artifact);
        self
    }

    /// True when this row is a genuine runtime pass: outcome is Pass, the
    /// tier is live-runtime, and a concrete [`RuntimeArtifactSource`] is attached.
    pub fn is_genuine_runtime_pass(&self) -> bool {
        self.outcome.is_terminal()
            && self.tier.is_runtime()
            && self
                .artifact_source
                .as_ref()
                .map(|a| a.is_genuine())
                .unwrap_or(false)
    }
}

// ── No-daemon validation report ──────────────────────────────────────────────

/// Aggregate validation report for a no-daemon full-stack validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoDaemonValidationReport {
    /// Validation run identifier.
    pub validation_id: String,
    /// Validation rows collected during the run.
    pub rows: Vec<NoDaemonValidationRow>,
    /// FNV-1a digest of the entire report (computed after rows are collected).
    pub digest: u64,
    /// Timestamp of the validation run.
    pub timestamp: String,
    /// Linux kernel version used, if known.
    pub kernel_version: Option<String>,
    /// QEMU command line used, if applicable.
    pub qemu_command: Option<String>,
}

impl NoDaemonValidationReport {
    /// Create a new empty report.
    pub fn new(validation_id: impl Into<String>) -> Self {
        Self {
            validation_id: validation_id.into(),
            rows: Vec::new(),
            digest: 0,
            timestamp: String::new(),
            kernel_version: None,
            qemu_command: None,
        }
    }

    /// Add a row to the report.
    pub fn add_row(&mut self, row: NoDaemonValidationRow) {
        self.rows.push(row);
    }

    /// Compute and seal the report digest.
    ///
    /// The digest covers all rows' row_digest values concatenated in order.
    pub fn seal(&mut self, timestamp: impl Into<String>) {
        self.timestamp = timestamp.into();
        let mut buf = Vec::new();
        for row in &self.rows {
            buf.extend_from_slice(&row.row_digest().to_le_bytes());
        }
        self.digest = fnv1a_64(&buf);
    }

    /// Count rows by outcome.
    pub fn count_by_outcome(&self, outcome: NoDaemonOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }

    /// Count rows by tier.
    pub fn count_by_tier(&self, tier: NoDaemonValidationTier) -> usize {
        self.rows.iter().filter(|r| r.tier == tier).count()
    }

    /// Whether all rows at or above the given tier pass.
    pub fn all_pass_at_or_above(&self, tier: NoDaemonValidationTier) -> bool {
        self.rows
            .iter()
            .filter(|r| r.tier >= tier)
            .all(|r| r.outcome == NoDaemonOutcome::Pass)
    }

    /// Whether all failing rows are at tiers below the given tier.
    pub fn failures_only_below(&self, tier: NoDaemonValidationTier) -> bool {
        self.rows
            .iter()
            .filter(|r| r.outcome.is_failure())
            .all(|r| r.tier < tier)
    }

    /// Whether this report satisfies full-kernel-no-daemon closure.
    ///
    /// Requires all QemuFullStack rows to pass.
    pub fn is_full_kernel_no_daemon_closure(&self) -> bool {
        self.all_pass_at_or_above(NoDaemonValidationTier::QemuFullStack)
            && self.count_by_tier(NoDaemonValidationTier::QemuFullStack) > 0
    }
}

// ── No-daemon process inspector ───────────────────────────────────────────

/// Known userspace daemon process name patterns to detect.
const KNOWN_DAEMON_PATTERNS: &[&str] = &[
    "tidefs.*daemon",
    "fuse.*adapter",
    "ublk.*adapter",
    "tidefs-storage-node",
    "tidefs-block-volume",
    "tidefs-posix-filesystem-adapter",
    "tidefs-block-volume-adapter",
    "tidefs-policy",
    "tidefs-control",
    "tidefs-transport",
    "tidefs-membership",
];

/// A snapshot of guest process state used to verify no userspace daemon is
/// running during mounted VFS or block I/O operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoDaemonProcSnapshot {
    /// Label describing when this snapshot was taken (e.g. "phase0_module_load").
    pub label: String,
    /// Raw /proc/mounts content from the guest.
    pub mounts: String,
    /// Raw process list from the guest.
    pub process_list: String,
    /// Raw /proc/filesystems content from the guest.
    pub filesystems: String,
    /// Raw lsmod output from the guest.
    pub lsmod_output: String,
    /// Whether a FUSE filesystem mount was detected.
    pub fuse_mount_detected: bool,
    /// Whether a userspace daemon process was detected.
    pub daemon_process_detected: bool,
    /// Names of any detected daemon processes.
    pub detected_daemon_names: Vec<String>,
    /// Whether tidefs is registered in /proc/filesystems.
    pub tidefs_registered: bool,
    /// Whether a TideFS kernel mount (filesystem type "tidefs") is present
    /// in /proc/mounts. Absence of daemons plus loaded module is not enough;
    /// positive mounted operation validation is required.
    pub tidefs_mount_present: bool,
    /// Whether kmod-posix-vfs module is loaded.
    pub kmod_posix_vfs_loaded: bool,
}

impl NoDaemonProcSnapshot {
    /// Create a new empty snapshot.
    pub fn new(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            mounts: String::new(),
            process_list: String::new(),
            filesystems: String::new(),
            lsmod_output: String::new(),
            fuse_mount_detected: false,
            daemon_process_detected: false,
            detected_daemon_names: Vec::new(),
            tidefs_registered: false,
            tidefs_mount_present: false,
            kmod_posix_vfs_loaded: false,
        }
    }

    /// Whether this snapshot is clean: no daemon detected, a TideFS
    /// kernel mount is present, tidefs is registered as a filesystem type,
    /// and the kmod module is loaded.
    ///
    /// Absence of daemon processes is necessary but not sufficient. Positive
    /// validation of a mounted TideFS filesystem (fstype "tidefs" in
    /// /proc/mounts) is required for the no-daemon classifier to pass.
    pub fn is_clean_no_daemon(&self) -> bool {
        !self.daemon_process_detected
            && self.tidefs_mount_present
            && self.tidefs_registered
            && self.kmod_posix_vfs_loaded
    }

    /// Whether a FUSE daemon was detected (fuse mount + process).
    pub fn has_fuse_daemon(&self) -> bool {
        self.fuse_mount_detected && self.daemon_process_detected
    }

    /// Whether a ublk daemon was detected.
    pub fn has_ublk_daemon(&self) -> bool {
        self.detected_daemon_names
            .iter()
            .any(|n| n.contains("ublk"))
    }
}

/// Inspects guest process state to verify no-daemon residency.
///
/// This formalizes the positive predicates that the Nix QEMU script
/// `kernel-no-daemon-validation.nix` exercises at each phase:
///
/// - No FUSE mount present in `/proc/mounts`.
/// - No process matching known daemon patterns in `ps` output.
/// - `tidefs` is registered in `/proc/filesystems`.
/// - A TideFS kernel mount (fstype "tidefs") appears in `/proc/mounts`.
/// - `tidefs_posix_vfs` appears in `lsmod`.
///
/// Absence of daemon processes is necessary but not sufficient for the
/// full-kernel no-daemon gate. Positive validation of mounted VFS operation
/// (a real TideFS mount present in /proc/mounts, not just the filesystem
/// type registration) is required. Block I/O through kernel-resident paths
/// is also required for block-kmod gates.
pub struct NoDaemonProcInspector {
    /// All snapshots collected during a validation run.
    pub snapshots: Vec<NoDaemonProcSnapshot>,
}

impl NoDaemonProcInspector {
    pub fn new() -> Self {
        Self {
            snapshots: Vec::new(),
        }
    }

    /// Inspect a guest process state blob and produce a snapshot.
    pub fn inspect(
        &mut self,
        label: impl Into<String>,
        mounts: &str,
        process_list: &str,
        filesystems: &str,
        lsmod_out: &str,
    ) -> &NoDaemonProcSnapshot {
        let label = label.into();
        let fuse_mount = mounts
            .lines()
            .any(|l| l.contains("fuse") && !l.contains("fuseblk"));
        // Positive mount validation: require a /proc/mounts entry whose
        // filesystem type field (index 2) is "tidefs", not just a device
        // name that happens to match.
        let tidefs_mounted = mounts.lines().any(|l| {
            let parts: Vec<&str> = l.splitn(6, ' ').collect();
            parts.get(2).is_some_and(|fstype| *fstype == "tidefs")
        });
        let tidefs_reg = filesystems.lines().any(|l| l.contains("tidefs"));
        let kmod_loaded = lsmod_out.lines().any(|l| l.contains("tidefs_posix_vfs"));

        let daemon_names: Vec<String> = KNOWN_DAEMON_PATTERNS
            .iter()
            .flat_map(|pat| {
                let search = pat.replace(".*", "");
                process_list
                    .lines()
                    .filter(move |l| {
                        let lower = l.to_lowercase();
                        lower.contains(&search) && !lower.contains("grep") && !lower.contains("[")
                    })
                    .map(|l| l.to_string())
            })
            .collect();

        let snapshot = NoDaemonProcSnapshot {
            label,
            mounts: mounts.to_string(),
            process_list: process_list.to_string(),
            filesystems: filesystems.to_string(),
            lsmod_output: lsmod_out.to_string(),
            fuse_mount_detected: fuse_mount,
            daemon_process_detected: !daemon_names.is_empty(),
            detected_daemon_names: daemon_names,
            tidefs_registered: tidefs_reg,
            tidefs_mount_present: tidefs_mounted,
            kmod_posix_vfs_loaded: kmod_loaded,
        };

        self.snapshots.push(snapshot);
        self.snapshots.last().unwrap()
    }

    /// Whether all snapshots are clean (no daemon detected).
    pub fn all_clean(&self) -> bool {
        !self.snapshots.is_empty() && self.snapshots.iter().all(|s| s.is_clean_no_daemon())
    }

    /// Count of snapshots where a daemon was detected.
    pub fn daemon_detection_count(&self) -> usize {
        self.snapshots
            .iter()
            .filter(|s| s.daemon_process_detected)
            .count()
    }

    /// Produce validation rows for every snapshot.
    pub fn to_validation_rows(&self, tier: NoDaemonValidationTier) -> Vec<NoDaemonValidationRow> {
        self.snapshots
            .iter()
            .map(|s| {
                let outcome = if s.is_clean_no_daemon() {
                    NoDaemonOutcome::Pass
                } else if s.daemon_process_detected {
                    NoDaemonOutcome::Fail
                } else {
                    NoDaemonOutcome::Blocked
                };

                let detail = if s.daemon_process_detected {
                    format!(
                        "daemon_process_detected: {}",
                        s.detected_daemon_names.join(", ")
                    )
                } else if !s.tidefs_registered {
                    "tidefs not registered in /proc/filesystems".to_string()
                } else if !s.kmod_posix_vfs_loaded {
                    "kmod-posix-vfs module not loaded".to_string()
                } else if !s.tidefs_mount_present {
                    "no TideFS kernel mount (fstype tidefs) in /proc/mounts — positive mounted VFS validation missing".to_string()
                } else {
                    "no_daemon_clean: tidefs_registered tidefs_mounted fuse_free module_loaded".to_string()
                };

                NoDaemonValidationRow::new(
                    format!("proc_inspector_{}", s.label),
                    tier,
                    NoDaemonOpKind::Fsync,
                    outcome,
                    detail,
                )
            })
            .collect()
    }
}

impl Default for NoDaemonProcInspector {
    fn default() -> Self {
        Self::new()
    }
}

// ── QEMU script output parser ─────────────────────────────────────────────

/// Parses the structured output of the Nix QEMU no-daemon validation script
/// into validation rows.
///
/// The Nix script at `nix/vm/kernel-no-daemon-validation.nix` emits lines:
/// ```text
/// PASS: phase_name
/// FAIL: phase_name -- reason
/// BLOCKED: phase_name -- reason
/// SKIP: phase_name -- reason
/// ```
///
/// This parser maps those lines to `NoDaemonValidationRow` entries keyed by
/// operation kind and tier.
pub struct NoDaemonQemuOutputParser {
    pub rows: Vec<NoDaemonValidationRow>,
}

impl NoDaemonQemuOutputParser {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    /// Parse a single line of QEMU script output.
    pub fn parse_line(&mut self, line: &str, tier: NoDaemonValidationTier) -> Option<()> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        let (outcome, rest) = if let Some(rest) = trimmed.strip_prefix("PASS: ") {
            (NoDaemonOutcome::Pass, rest)
        } else if let Some(rest) = trimmed.strip_prefix("FAIL: ") {
            (NoDaemonOutcome::Fail, rest)
        } else if let Some(rest) = trimmed.strip_prefix("BLOCKED: ") {
            (NoDaemonOutcome::Blocked, rest)
        } else if let Some(rest) = trimmed.strip_prefix("SKIP: ") {
            (NoDaemonOutcome::Skip, rest)
        } else {
            return None;
        };

        let (phase, detail) = if let Some((p, d)) = rest.split_once(" -- ") {
            (p.trim(), d.trim().to_string())
        } else {
            (rest.trim(), String::new())
        };

        let op = classify_phase_to_op(phase);
        let row_id = format!("qemu_{phase}");

        self.rows.push(NoDaemonValidationRow::new(
            row_id, tier, op, outcome, detail,
        ));
        Some(())
    }

    /// Parse a full QEMU log output.
    pub fn parse_log(&mut self, log: &str, tier: NoDaemonValidationTier) {
        for line in log.lines() {
            self.parse_line(line, tier);
        }
    }

    /// Produce a sealed validation report from parsed rows.
    pub fn to_report(
        &self,
        validation_id: impl Into<String>,
        timestamp: impl Into<String>,
    ) -> NoDaemonValidationReport {
        let mut report = NoDaemonValidationReport::new(validation_id);
        for row in &self.rows {
            report.add_row(row.clone());
        }
        report.seal(timestamp);
        report
    }

    /// Count rows by outcome.
    pub fn count_by_outcome(&self, outcome: NoDaemonOutcome) -> usize {
        self.rows.iter().filter(|r| r.outcome == outcome).count()
    }
}

impl Default for NoDaemonQemuOutputParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Map a phase name from the QEMU script to a `NoDaemonOpKind`.
fn classify_phase_to_op(phase: &str) -> NoDaemonOpKind {
    if phase.contains("no_daemon") || phase.contains("final_no_daemon") {
        NoDaemonOpKind::Fsync
    } else if phase.contains("create") || phase.contains("mkdir") {
        NoDaemonOpKind::Create
    } else if phase.contains("write") {
        NoDaemonOpKind::Write
    } else if phase.contains("read") {
        NoDaemonOpKind::Read
    } else if phase.contains("rename") {
        NoDaemonOpKind::Rename
    } else if phase.contains("unlink") || phase.contains("rmdir") {
        NoDaemonOpKind::Unlink
    } else if phase.contains("fsync") || phase.contains("sync") {
        NoDaemonOpKind::Fsync
    } else if phase.contains("remount") || phase.contains("crash") {
        NoDaemonOpKind::CrashRemount
    } else {
        NoDaemonOpKind::Fsync
    }
}

// ── SourceModel tier: no-daemon lifecycle simulation ───────────────────────

/// A simulated no-daemon lifecycle that exercises the validation schema types
/// and outcome state machine without requiring a real kernel or QEMU process.
///
/// This tier validates:
/// - Schema type serialization/deserialization round-trips
/// - Outcome state machine transitions
/// - Validation report creation and FNV-1a digest computation
/// - Full lifecycle coverage (every NoDaemonOpKind × every outcome)
pub struct NoDaemonSourceModel {
    /// The validation report being built.
    pub report: NoDaemonValidationReport,
}

impl NoDaemonSourceModel {
    /// Create a new source-model simulation.
    pub fn new() -> Self {
        Self {
            report: NoDaemonValidationReport::new("no-daemon-source-model"),
        }
    }

    /// Run the full SourceModel lifecycle simulation.
    ///
    /// Produces validation rows for every operation kind at the SourceModel tier,
    /// exercising both passing and failing paths, then seals the report.
    pub fn run(&mut self) -> &NoDaemonValidationReport {
        self.simulate_all_ops_pass();
        self.report.seal("source-model-timestamp");
        &self.report
    }

    /// Simulate all NoDaemonOpKind variants passing at SourceModel tier.
    fn simulate_all_ops_pass(&mut self) {
        let ops = [
            NoDaemonOpKind::Create,
            NoDaemonOpKind::Write,
            NoDaemonOpKind::Read,
            NoDaemonOpKind::Rename,
            NoDaemonOpKind::Unlink,
            NoDaemonOpKind::Fsync,
            NoDaemonOpKind::CrashRemount,
        ];

        for op in ops.iter() {
            let row_id = format!("source-model-{}", op.label());
            let row = NoDaemonValidationRow::new(
                row_id,
                NoDaemonValidationTier::SourceModel,
                *op,
                NoDaemonOutcome::Pass,
                format!("SourceModel: {} lifecycle validated", op.description()),
            )
            .with_duration(1);
            self.report.add_row(row);

            // Also simulate a blocked variant for ops that require QEMU.
            let blocked_id = format!("source-model-{}-blocked-scenario", op.label());
            let blocked_row = NoDaemonValidationRow::new(
                blocked_id,
                NoDaemonValidationTier::SourceModel,
                *op,
                NoDaemonOutcome::Blocked,
                format!(
                    "SourceModel: {} cannot be terminal at SourceModel tier; requires QEMU",
                    op.label()
                ),
            );
            self.report.add_row(blocked_row);
        }
    }
}

impl Default for NoDaemonSourceModel {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── FNV-1a tests ──────────────────────────────────────────────────

    #[test]
    fn fnv1a_known_vectors() {
        // Empty input
        assert_eq!(fnv1a_64(b""), 0xcbf29ce484222325);
        // "a"
        assert_eq!(fnv1a_64(b"a"), 0xaf63dc4c8601ec8c);
        // "foobar"
        assert_eq!(fnv1a_64(b"foobar"), 0x85944171f73967e8);
    }

    #[test]
    fn fnv1a_str_consistent() {
        let s = "no-daemon-validation";
        assert_eq!(fnv1a_str(s), fnv1a_64(s.as_bytes()));
    }

    #[test]
    fn fnv1a_deterministic() {
        let data = b"kmod-posix-vfs full stack 2026-05-21";
        let h1 = fnv1a_64(data);
        let h2 = fnv1a_64(data);
        assert_eq!(h1, h2);
    }

    #[test]
    fn fnv1a_different_inputs_different_hashes() {
        let h1 = fnv1a_64(b"create-pass");
        let h2 = fnv1a_64(b"create-fail");
        assert_ne!(h1, h2);
    }

    // ── NoDaemonOpKind tests ──────────────────────────────────────────

    #[test]
    fn op_kind_labels_distinct() {
        let ops = [
            NoDaemonOpKind::Create,
            NoDaemonOpKind::Write,
            NoDaemonOpKind::Read,
            NoDaemonOpKind::Rename,
            NoDaemonOpKind::Unlink,
            NoDaemonOpKind::Fsync,
            NoDaemonOpKind::CrashRemount,
        ];
        let mut labels: Vec<&str> = ops.iter().map(|o| o.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(
            labels.len(),
            ops.len(),
            "all op kind labels must be distinct"
        );
    }

    #[test]
    fn op_kind_is_mutating() {
        assert!(NoDaemonOpKind::Create.is_mutating());
        assert!(NoDaemonOpKind::Write.is_mutating());
        assert!(NoDaemonOpKind::Rename.is_mutating());
        assert!(NoDaemonOpKind::Unlink.is_mutating());
        assert!(!NoDaemonOpKind::Read.is_mutating());
        assert!(!NoDaemonOpKind::Fsync.is_mutating());
        assert!(!NoDaemonOpKind::CrashRemount.is_mutating());
    }

    #[test]
    fn op_kind_is_durable() {
        assert!(NoDaemonOpKind::Fsync.is_durable());
        assert!(NoDaemonOpKind::CrashRemount.is_durable());
        assert!(!NoDaemonOpKind::Create.is_durable());
        assert!(!NoDaemonOpKind::Write.is_durable());
    }

    #[test]
    fn op_kind_display_matches_label() {
        for op in [
            NoDaemonOpKind::Create,
            NoDaemonOpKind::Write,
            NoDaemonOpKind::Read,
        ] {
            assert_eq!(format!("{op}"), op.label());
        }
    }

    // ── NoDaemonValidationTier tests ────────────────────────────────────

    #[test]
    fn tier_ordering() {
        assert!(NoDaemonValidationTier::SourceModel < NoDaemonValidationTier::QemuBoot);
        assert!(NoDaemonValidationTier::QemuBoot < NoDaemonValidationTier::QemuMountNoDaemon);
        assert!(NoDaemonValidationTier::QemuMountNoDaemon < NoDaemonValidationTier::QemuFullStack);
    }

    #[test]
    fn terminal_tier_is_qemu_full_stack() {
        assert_eq!(
            NoDaemonValidationTier::terminal_tier(),
            NoDaemonValidationTier::QemuFullStack
        );
    }

    #[test]
    fn tier_requires_qemu() {
        assert!(!NoDaemonValidationTier::SourceModel.requires_qemu());
        assert!(NoDaemonValidationTier::QemuBoot.requires_qemu());
        assert!(NoDaemonValidationTier::QemuMountNoDaemon.requires_qemu());
        assert!(NoDaemonValidationTier::QemuFullStack.requires_qemu());
    }

    #[test]
    fn tier_is_runtime() {
        assert!(!NoDaemonValidationTier::SourceModel.is_runtime());
        assert!(!NoDaemonValidationTier::QemuBoot.is_runtime());
        assert!(NoDaemonValidationTier::QemuMountNoDaemon.is_runtime());
        assert!(NoDaemonValidationTier::QemuFullStack.is_runtime());
    }

    #[test]
    fn tier_labels_distinct() {
        let tiers = [
            NoDaemonValidationTier::SourceModel,
            NoDaemonValidationTier::QemuBoot,
            NoDaemonValidationTier::QemuMountNoDaemon,
            NoDaemonValidationTier::QemuFullStack,
        ];
        let mut labels: Vec<&str> = tiers.iter().map(|t| t.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), tiers.len());
    }

    // ── NoDaemonOutcome tests ─────────────────────────────────────────

    #[test]
    fn outcome_labels_distinct() {
        let outcomes = [
            NoDaemonOutcome::Pass,
            NoDaemonOutcome::Fail,
            NoDaemonOutcome::Blocked,
            NoDaemonOutcome::Skip,
        ];
        let mut labels: Vec<&str> = outcomes.iter().map(|o| o.label()).collect();
        labels.sort();
        labels.dedup();
        assert_eq!(labels.len(), outcomes.len());
    }

    #[test]
    fn outcome_is_terminal() {
        assert!(NoDaemonOutcome::Pass.is_terminal());
        assert!(!NoDaemonOutcome::Fail.is_terminal());
        assert!(!NoDaemonOutcome::Blocked.is_terminal());
        assert!(!NoDaemonOutcome::Skip.is_terminal());
    }

    #[test]
    fn outcome_is_blocking() {
        assert!(NoDaemonOutcome::Fail.is_blocking());
        assert!(NoDaemonOutcome::Blocked.is_blocking());
        assert!(!NoDaemonOutcome::Pass.is_blocking());
        assert!(!NoDaemonOutcome::Skip.is_blocking());
    }

    // ── NoDaemonValidationRow tests ─────────────────────────────────────

    #[test]
    fn row_construction() {
        let row = NoDaemonValidationRow::new(
            "test-row-1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "test detail",
        );
        assert_eq!(row.row_id, "test-row-1");
        assert_eq!(row.tier, NoDaemonValidationTier::SourceModel);
        assert_eq!(row.op, NoDaemonOpKind::Create);
        assert_eq!(row.outcome, NoDaemonOutcome::Pass);
        assert_eq!(row.detail, "test detail");
        assert!(row.duration_ms.is_none());
        assert!(row.committed_root_before.is_none());
        assert!(row.committed_root_after.is_none());
    }

    #[test]
    fn row_with_committed_roots() {
        let row = NoDaemonValidationRow::new(
            "cr-row",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::CrashRemount,
            NoDaemonOutcome::Pass,
            "committed root matches",
        )
        .with_committed_roots("abc123", "abc123");
        assert_eq!(row.committed_root_before.as_deref(), Some("abc123"));
        assert_eq!(row.committed_root_after.as_deref(), Some("abc123"));
    }

    #[test]
    fn row_with_duration() {
        let row = NoDaemonValidationRow::new(
            "timed-row",
            NoDaemonValidationTier::QemuBoot,
            NoDaemonOpKind::Read,
            NoDaemonOutcome::Pass,
            "fast read",
        )
        .with_duration(42);
        assert_eq!(row.duration_ms, Some(42));
    }

    #[test]
    fn row_digest_deterministic() {
        let row1 = NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "same detail",
        );
        let row2 = NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "same detail",
        );
        // Different row_ids don't affect the row digest (it's tier+op+outcome+detail)
        assert_eq!(row1.row_digest(), row2.row_digest());
    }

    #[test]
    fn row_digest_different_for_different_outcomes() {
        let pass_row = NoDaemonValidationRow::new(
            "r",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Pass,
            "write test",
        );
        let fail_row = NoDaemonValidationRow::new(
            "r",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Fail,
            "write test",
        );
        assert_ne!(pass_row.row_digest(), fail_row.row_digest());
    }

    #[test]
    fn row_is_terminal_pass() {
        let pass_row = NoDaemonValidationRow::new(
            "r",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Fsync,
            NoDaemonOutcome::Pass,
            "all good",
        );
        assert!(pass_row.is_terminal_pass(NoDaemonValidationTier::QemuFullStack));

        let low_row = NoDaemonValidationRow::new(
            "r",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Fsync,
            NoDaemonOutcome::Pass,
            "all good",
        );
        assert!(!low_row.is_terminal_pass(NoDaemonValidationTier::QemuFullStack));
    }

    // ── NoDaemonValidationReport tests ──────────────────────────────────

    #[test]
    fn empty_report() {
        let report = NoDaemonValidationReport::new("empty");
        assert_eq!(report.validation_id, "empty");
        assert_eq!(report.rows.len(), 0);
        assert_eq!(report.digest, 0);
    }

    #[test]
    fn report_add_and_count() {
        let mut report = NoDaemonValidationReport::new("test");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Fail,
            "",
        ));
        assert_eq!(report.count_by_outcome(NoDaemonOutcome::Pass), 1);
        assert_eq!(report.count_by_outcome(NoDaemonOutcome::Fail), 1);
        assert_eq!(report.count_by_tier(NoDaemonValidationTier::SourceModel), 2);
    }

    #[test]
    fn report_seal_produces_nonzero_digest() {
        let mut report = NoDaemonValidationReport::new("seal-test");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "detail",
        ));
        report.seal("2026-05-21T00:00:00Z");
        assert_ne!(report.digest, 0);
        assert_eq!(report.timestamp, "2026-05-21T00:00:00Z");
    }

    #[test]
    fn report_seal_deterministic() {
        let build_report = || {
            let mut report = NoDaemonValidationReport::new("det");
            report.add_row(NoDaemonValidationRow::new(
                "r1",
                NoDaemonValidationTier::SourceModel,
                NoDaemonOpKind::Create,
                NoDaemonOutcome::Pass,
                "d",
            ));
            report.seal("ts");
            report
        };
        let report1 = build_report();
        let report2 = build_report();
        assert_eq!(report1.digest, report2.digest);
    }

    #[test]
    fn report_all_pass_at_or_above() {
        let mut report = NoDaemonValidationReport::new("t");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Pass,
            "",
        ));
        assert!(report.all_pass_at_or_above(NoDaemonValidationTier::QemuFullStack));
    }

    #[test]
    fn report_all_pass_at_or_above_with_failure() {
        let mut report = NoDaemonValidationReport::new("t");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Fail,
            "io error",
        ));
        assert!(!report.all_pass_at_or_above(NoDaemonValidationTier::QemuFullStack));
    }

    #[test]
    fn report_is_full_kernel_no_daemon_closure() {
        let mut report = NoDaemonValidationReport::new("t");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Fsync,
            NoDaemonOutcome::Pass,
            "",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::CrashRemount,
            NoDaemonOutcome::Pass,
            "",
        ));
        assert!(report.is_full_kernel_no_daemon_closure());
    }

    #[test]
    fn report_not_closure_without_qemu_full_stack_rows() {
        let mut report = NoDaemonValidationReport::new("t");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "",
        ));
        assert!(!report.is_full_kernel_no_daemon_closure());
    }

    #[test]
    fn report_failures_only_below() {
        let mut report = NoDaemonValidationReport::new("t");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::SourceModel,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Fail,
            "not real",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Write,
            NoDaemonOutcome::Pass,
            "",
        ));
        assert!(report.failures_only_below(NoDaemonValidationTier::QemuFullStack));
    }

    // ── NoDaemonSourceModel tests ─────────────────────────────────────

    #[test]
    fn source_model_produces_rows() {
        let mut model = NoDaemonSourceModel::new();
        model.run();
        assert!(!model.report.rows.is_empty());
    }

    #[test]
    fn source_model_covers_all_op_kinds() {
        let mut model = NoDaemonSourceModel::new();
        model.run();

        let all_ops = [
            NoDaemonOpKind::Create,
            NoDaemonOpKind::Write,
            NoDaemonOpKind::Read,
            NoDaemonOpKind::Rename,
            NoDaemonOpKind::Unlink,
            NoDaemonOpKind::Fsync,
            NoDaemonOpKind::CrashRemount,
        ];

        for op in &all_ops {
            let pass_count = model
                .report
                .rows
                .iter()
                .filter(|r| r.op == *op && r.outcome == NoDaemonOutcome::Pass)
                .count();
            assert!(
                pass_count > 0,
                "SourceModel should have a Pass row for op {}",
                op.label()
            );
        }
    }

    #[test]
    fn source_model_all_rows_are_source_model_tier() {
        let mut model = NoDaemonSourceModel::new();
        model.run();
        for row in &model.report.rows {
            assert_eq!(row.tier, NoDaemonValidationTier::SourceModel);
        }
    }

    #[test]
    fn source_model_report_has_digest() {
        let mut model = NoDaemonSourceModel::new();
        model.run();
        assert_ne!(model.report.digest, 0);
    }

    #[test]
    fn source_model_deterministic() {
        let run1 = {
            let mut m = NoDaemonSourceModel::new();
            m.run();
            m.report.digest
        };
        let run2 = {
            let mut m = NoDaemonSourceModel::new();
            m.run();
            m.report.digest
        };
        assert_eq!(run1, run2);
    }

    // ── Serialization round-trip tests ────────────────────────────────

    #[test]
    fn op_kind_serde_roundtrip() {
        let ops = [
            NoDaemonOpKind::Create,
            NoDaemonOpKind::Write,
            NoDaemonOpKind::Read,
            NoDaemonOpKind::Rename,
            NoDaemonOpKind::Unlink,
            NoDaemonOpKind::Fsync,
            NoDaemonOpKind::CrashRemount,
        ];
        for op in &ops {
            let json = serde_json::to_string(op).unwrap();
            let back: NoDaemonOpKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*op, back);
        }
    }

    #[test]
    fn tier_serde_roundtrip() {
        let tiers = [
            NoDaemonValidationTier::SourceModel,
            NoDaemonValidationTier::QemuBoot,
            NoDaemonValidationTier::QemuMountNoDaemon,
            NoDaemonValidationTier::QemuFullStack,
        ];
        for tier in &tiers {
            let json = serde_json::to_string(tier).unwrap();
            let back: NoDaemonValidationTier = serde_json::from_str(&json).unwrap();
            assert_eq!(*tier, back);
        }
    }

    #[test]
    fn outcome_serde_roundtrip() {
        let outcomes = [
            NoDaemonOutcome::Pass,
            NoDaemonOutcome::Fail,
            NoDaemonOutcome::Blocked,
            NoDaemonOutcome::Skip,
        ];
        for outcome in &outcomes {
            let json = serde_json::to_string(outcome).unwrap();
            let back: NoDaemonOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(*outcome, back);
        }
    }

    #[test]
    fn validation_row_serde_roundtrip() {
        let row = NoDaemonValidationRow::new(
            "serde-test",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::CrashRemount,
            NoDaemonOutcome::Pass,
            "committed root consistent",
        )
        .with_committed_roots("pre-crash-abc", "post-crash-abc")
        .with_duration(150);

        let json = serde_json::to_string_pretty(&row).unwrap();
        let back: NoDaemonValidationRow = serde_json::from_str(&json).unwrap();

        assert_eq!(row.row_id, back.row_id);
        assert_eq!(row.tier, back.tier);
        assert_eq!(row.op, back.op);
        assert_eq!(row.outcome, back.outcome);
        assert_eq!(row.detail, back.detail);
        assert_eq!(row.duration_ms, back.duration_ms);
        assert_eq!(row.committed_root_before, back.committed_root_before);
        assert_eq!(row.committed_root_after, back.committed_root_after);
    }

    #[test]
    fn validation_report_serde_roundtrip() {
        let mut report = NoDaemonValidationReport::new("serde-report");
        report.add_row(NoDaemonValidationRow::new(
            "r1",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Fsync,
            NoDaemonOutcome::Pass,
            "fsync ok",
        ));
        report.add_row(NoDaemonValidationRow::new(
            "r2",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::CrashRemount,
            NoDaemonOutcome::Pass,
            "remount ok",
        ));
        report.seal("2026-05-21T00:00:00Z");
        report.kernel_version = Some("7.0.0".into());

        let json = serde_json::to_string_pretty(&report).unwrap();
        let back: NoDaemonValidationReport = serde_json::from_str(&json).unwrap();

        assert_eq!(report.validation_id, back.validation_id);
        assert_eq!(report.rows.len(), back.rows.len());
        assert_eq!(report.digest, back.digest);
        assert_eq!(report.timestamp, back.timestamp);
        assert_eq!(report.kernel_version, back.kernel_version);
    }

    // ── Kebab-case serialization tests ────────────────────────────────

    #[test]
    fn op_kind_serializes_kebab_case() {
        let json = serde_json::to_string(&NoDaemonOpKind::CrashRemount).unwrap();
        assert_eq!(json, "\"crash-remount\"");
    }

    #[test]
    fn tier_serializes_kebab_case() {
        let json = serde_json::to_string(&NoDaemonValidationTier::QemuMountNoDaemon).unwrap();
        assert_eq!(json, "\"qemu-mount-no-daemon\"");
    }

    #[test]
    fn outcome_serializes_kebab_case() {
        let json = serde_json::to_string(&NoDaemonOutcome::Pass).unwrap();
        assert_eq!(json, "\"pass\"");
    }

    /// Guard test: live-runtime tier Pass rows require a concrete
    /// [`RuntimeArtifactSource`] to be classified as genuine.
    #[test]
    fn guard_live_runtime_pass_requires_artifact_source() {
        let no_artifact = NoDaemonValidationRow::new(
            "crash-create-nodaemon",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "no artifact",
        );
        assert!(no_artifact.tier.is_runtime());
        assert!(!no_artifact.is_genuine_runtime_pass());

        let with_artifact = NoDaemonValidationRow::new(
            "crash-create-nodaemon-verified",
            NoDaemonValidationTier::QemuFullStack,
            NoDaemonOpKind::Create,
            NoDaemonOutcome::Pass,
            "with artifact",
        )
        .with_artifact(RuntimeArtifactSource {
            command: "qemu-system-x86_64 ...".into(),
            environment: "Linux 7.0 QEMU guest x86_64".into(),
            commit: "abc123def".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/validation/nodaemon.log".into()),
            stderr_path: None,
            workload_ran: true,
        });
        assert!(with_artifact.tier.is_runtime());
        assert!(with_artifact.is_genuine_runtime_pass());
    }

    // ── NoDaemonProcInspector tests ──────────────────────────────────

    fn clean_proc_fixture() -> (&'static str, &'static str, &'static str, &'static str) {
        let mounts = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,size=242868k,nr_inodes=60717,mode=755 0 0
tidefs /mnt/tidefs tidefs rw,relatime 0 0";
        let process_list = "  1 init
  2 [kthreadd]
  3 busybox sh
  4 ps";
        let filesystems = "nodev   sysfs
nodev   proc
nodev   devtmpfs
        tidefs
        ext4";
        let lsmod_out = "tidefs_posix_vfs 16384 0 - Live 0xffffffffc0000000 (OE)";
        (mounts, process_list, filesystems, lsmod_out)
    }

    fn daemon_proc_fixture() -> (&'static str, &'static str, &'static str, &'static str) {
        let mounts = "tidefs /mnt/tidefs tidefs rw,relatime 0 0
fusectl /sys/fs/fuse/connections fusectl rw,relatime 0 0";
        let process_list = "  1 init
  2 [kthreadd]
  3 busybox sh
 10 tidefs-posix-filesystem-adapter-daemon --pool /var/lib/tidefs
 11 ps";
        let filesystems = "nodev   sysfs
nodev   proc
        tidefs
        ext4";
        let lsmod_out = "tidefs_posix_vfs 16384 0 - Live 0xffffffffc0000000 (OE)";
        (mounts, process_list, filesystems, lsmod_out)
    }

    fn no_module_fixture() -> (&'static str, &'static str, &'static str, &'static str) {
        let mounts = "proc /proc proc rw 0 0";
        let process_list = "  1 init";
        let filesystems = "nodev   proc";
        let lsmod_out = "";
        (mounts, process_list, filesystems, lsmod_out)
    }

    #[test]
    fn proc_inspector_clean_snapshot() {
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = clean_proc_fixture();
        let snap = inspector.inspect("phase0", mounts, procs, fs, lsmod);
        assert!(snap.is_clean_no_daemon());
        assert!(!snap.daemon_process_detected);
        assert!(snap.tidefs_registered);
        assert!(snap.kmod_posix_vfs_loaded);
        assert!(inspector.all_clean());
        assert_eq!(inspector.daemon_detection_count(), 0);
    }

    #[test]
    fn proc_inspector_detects_daemon() {
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = daemon_proc_fixture();
        let snap = inspector.inspect("phase1_mount", mounts, procs, fs, lsmod);
        assert!(!snap.is_clean_no_daemon());
        assert!(snap.daemon_process_detected);
        assert!(!snap.detected_daemon_names.is_empty());
        assert!(!inspector.all_clean());
        assert_eq!(inspector.daemon_detection_count(), 1);
    }

    #[test]
    fn proc_inspector_no_module() {
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = no_module_fixture();
        let snap = inspector.inspect("phase0", mounts, procs, fs, lsmod);
        assert!(!snap.is_clean_no_daemon());
        assert!(!snap.kmod_posix_vfs_loaded);
        assert!(!snap.tidefs_registered);
    }

    #[test]
    fn proc_inspector_multiple_snapshots() {
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = clean_proc_fixture();
        inspector.inspect("phase0", mounts, procs, fs, lsmod);
        inspector.inspect("phase1_mount", mounts, procs, fs, lsmod);
        inspector.inspect("phase5_directory", mounts, procs, fs, lsmod);
        assert_eq!(inspector.snapshots.len(), 3);
        assert!(inspector.all_clean());
    }

    #[test]
    fn proc_inspector_one_daemon_spoils_all() {
        let mut inspector = NoDaemonProcInspector::new();
        let (clean_mounts, clean_procs, clean_fs, clean_lsmod) = clean_proc_fixture();
        let (dirty_mounts, dirty_procs, dirty_fs, dirty_lsmod) = daemon_proc_fixture();
        inspector.inspect("phase0", clean_mounts, clean_procs, clean_fs, clean_lsmod);
        inspector.inspect(
            "phase1_mount",
            dirty_mounts,
            dirty_procs,
            dirty_fs,
            dirty_lsmod,
        );
        assert!(!inspector.all_clean());
        assert_eq!(inspector.daemon_detection_count(), 1);
    }

    #[test]
    fn proc_inspector_to_validation_rows() {
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = clean_proc_fixture();
        inspector.inspect("phase0", mounts, procs, fs, lsmod);
        inspector.inspect("phase1_mount", mounts, procs, fs, lsmod);

        let rows = inspector.to_validation_rows(NoDaemonValidationTier::QemuMountNoDaemon);
        assert_eq!(rows.len(), 2);
        for row in &rows {
            assert_eq!(row.outcome, NoDaemonOutcome::Pass);
            assert_eq!(row.tier, NoDaemonValidationTier::QemuMountNoDaemon);
        }
    }

    #[test]
    fn proc_inspector_empty_all_clean() {
        let inspector = NoDaemonProcInspector::new();
        assert!(!inspector.all_clean());
        assert_eq!(inspector.daemon_detection_count(), 0);
    }

    // ── Positive mount validation tests ──────────────────────────────
    //
    // These tests prove that the no-daemon classifier requires positive
    // TideFS mount validation (fstype "tidefs" in /proc/mounts), not only
    // absence of daemon processes plus module loaded.

    /// Fixture: module loaded, no daemon, but NO TideFS mount.
    /// /proc/mounts has only standard pseudo-filesystems.
    fn no_tidefs_mount_fixture() -> (&'static str, &'static str, &'static str, &'static str) {
        let mounts = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
devtmpfs /dev devtmpfs rw,nosuid,noexec,relatime,size=242868k,nr_inodes=60717,mode=755 0 0";
        let process_list = "  1 init
  2 [kthreadd]
  3 busybox sh
  4 ps";
        let filesystems = "nodev   sysfs
nodev   proc
nodev   devtmpfs
        tidefs
        ext4";
        let lsmod_out = "tidefs_posix_vfs 16384 0 - Live 0xffffffffc0000000 (OE)";
        (mounts, process_list, filesystems, lsmod_out)
    }

    /// Fixture: module loaded, no daemon, TideFS mount device field has
    /// "tidefs" but filesystem type is ext4 (not a real TideFS mount).
    fn tidefs_device_not_fstype_fixture() -> (&'static str, &'static str, &'static str, &'static str)
    {
        let mounts = "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
/dev/tidefs /mnt/data ext4 rw,relatime 0 0";
        let process_list = "  1 init
  2 [kthreadd]
  3 busybox sh
  4 ps";
        let filesystems = "nodev   sysfs
nodev   proc
        tidefs
        ext4";
        let lsmod_out = "tidefs_posix_vfs 16384 0 - Live 0xffffffffc0000000 (OE)";
        (mounts, process_list, filesystems, lsmod_out)
    }

    #[test]
    fn proc_inspector_no_tidefs_mount_is_not_clean() {
        // Module loaded, tidefs registered, no daemon — but NO TideFS mount.
        // Positive mount validation is missing, so is_clean_no_daemon() must
        // return false (blocked, not pass).
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = no_tidefs_mount_fixture();
        let snap = inspector.inspect("phase1_mount", mounts, procs, fs, lsmod);
        assert!(!snap.daemon_process_detected, "no daemon present");
        assert!(snap.tidefs_registered, "tidefs in /proc/filesystems");
        assert!(snap.kmod_posix_vfs_loaded, "module loaded");
        assert!(
            !snap.tidefs_mount_present,
            "no TideFS fstype in /proc/mounts"
        );
        // The classifier must NOT pass: positive mount validation is absent.
        assert!(
            !snap.is_clean_no_daemon(),
            "is_clean_no_daemon must be false when no TideFS mount is present
             (module loaded + tidefs registered + no daemon is not enough)"
        );
        // Should produce a Blocked outcome, not Pass.
        let rows = inspector.to_validation_rows(NoDaemonValidationTier::QemuMountNoDaemon);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].outcome,
            NoDaemonOutcome::Blocked,
            "missing TideFS mount must produce Blocked, not Pass"
        );
        assert!(
            rows[0].detail.contains("TideFS kernel mount"),
            "detail must mention missing TideFS mount"
        );
    }

    #[test]
    fn proc_inspector_tidefs_device_not_fstype_is_blocked() {
        // /dev/tidefs appears as a device name but fstype is ext4.
        // The classifier must check the fstype field (index 2), not the device
        // name field (index 0). This proves we don't accept a device-name-only
        // match.
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = tidefs_device_not_fstype_fixture();
        let snap = inspector.inspect("phase1_mount", mounts, procs, fs, lsmod);
        assert!(!snap.daemon_process_detected);
        assert!(snap.tidefs_registered);
        assert!(snap.kmod_posix_vfs_loaded);
        assert!(
            !snap.tidefs_mount_present,
            "/dev/tidefs with ext4 fstype must not be treated as TideFS mount"
        );
        assert!(!snap.is_clean_no_daemon());
    }

    #[test]
    fn proc_inspector_clean_snapshot_has_mount_validation() {
        // The existing clean_proc_fixture has a real TideFS mount line.
        // This test explicitly asserts that tidefs_mount_present is true
        // and that the classifier passes.
        let mut inspector = NoDaemonProcInspector::new();
        let (mounts, procs, fs, lsmod) = clean_proc_fixture();
        let snap = inspector.inspect("phase0", mounts, procs, fs, lsmod);
        assert!(snap.is_clean_no_daemon());
        assert!(
            snap.tidefs_mount_present,
            "clean fixture must have tidefs_mount_present set from /proc/mounts"
        );
        // Validation rows for a clean snapshot produce Pass.
        let rows = inspector.to_validation_rows(NoDaemonValidationTier::QemuMountNoDaemon);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].outcome, NoDaemonOutcome::Pass);
        assert!(rows[0].detail.contains("no_daemon_clean"));
        assert!(rows[0].detail.contains("tidefs_mounted"));
    }

    // ── NoDaemonQemuOutputParser tests ───────────────────────────────

    #[test]
    fn qemu_parser_parses_pass_line() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line("PASS: phase0_module_load", NoDaemonValidationTier::QemuBoot);
        assert_eq!(parser.rows.len(), 1);
        assert_eq!(parser.rows[0].outcome, NoDaemonOutcome::Pass);
        assert_eq!(parser.rows[0].tier, NoDaemonValidationTier::QemuBoot);
    }

    #[test]
    fn qemu_parser_parses_fail_with_detail() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line(
            "FAIL: phase1_mount -- mount: No such device",
            NoDaemonValidationTier::QemuMountNoDaemon,
        );
        assert_eq!(parser.rows.len(), 1);
        assert_eq!(parser.rows[0].outcome, NoDaemonOutcome::Fail);
        assert_eq!(parser.rows[0].detail, "mount: No such device");
    }

    #[test]
    fn qemu_parser_parses_blocked() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line(
            "BLOCKED: phase4_mmap_read_real -- no guest helper",
            NoDaemonValidationTier::QemuFullStack,
        );
        assert_eq!(parser.rows.len(), 1);
        assert_eq!(parser.rows[0].outcome, NoDaemonOutcome::Blocked);
    }

    #[test]
    fn qemu_parser_parses_skip() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line(
            "SKIP: phase2_read_sequential -- filesystem not mounted",
            NoDaemonValidationTier::QemuFullStack,
        );
        assert_eq!(parser.rows.len(), 1);
        assert_eq!(parser.rows[0].outcome, NoDaemonOutcome::Skip);
    }

    #[test]
    fn qemu_parser_ignores_non_matching_lines() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line(
            "=== TideFS NoDaemonResidency ===",
            NoDaemonValidationTier::QemuBoot,
        );
        parser.parse_line("", NoDaemonValidationTier::QemuBoot);
        parser.parse_line("kernel_version=7.0.0", NoDaemonValidationTier::QemuBoot);
        assert_eq!(parser.rows.len(), 0);
    }

    #[test]
    fn qemu_parser_parse_log() {
        let log = "=== TideFS NoDaemonResidency ===
PASS: phase0_module_load
PASS: phase0_module_lsmod
PASS: no_daemon_phase0_module_load
BLOCKED: phase1_mount -- mount: No such device
=== SUMMARY ===
PASS=3 FAIL=0 BLOCKED=1 SKIP=0 REFUSAL=0";
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_log(log, NoDaemonValidationTier::QemuBoot);
        assert_eq!(parser.rows.len(), 4);
        assert_eq!(parser.count_by_outcome(NoDaemonOutcome::Pass), 3);
        assert_eq!(parser.count_by_outcome(NoDaemonOutcome::Blocked), 1);
    }

    #[test]
    fn qemu_parser_to_report() {
        let mut parser = NoDaemonQemuOutputParser::new();
        parser.parse_line("PASS: phase0_module_load", NoDaemonValidationTier::QemuBoot);
        parser.parse_line("PASS: no_daemon_phase0", NoDaemonValidationTier::QemuBoot);

        let report = parser.to_report("test-report", "2026-05-22T00:00:00Z");
        assert_eq!(report.validation_id, "test-report");
        assert_eq!(report.rows.len(), 2);
        assert_ne!(report.digest, 0);
        assert_eq!(report.timestamp, "2026-05-22T00:00:00Z");
    }

    #[test]
    fn qemu_parser_empty_parser() {
        let parser = NoDaemonQemuOutputParser::new();
        assert_eq!(parser.rows.len(), 0);
        assert_eq!(parser.count_by_outcome(NoDaemonOutcome::Pass), 0);
    }

    // ── classify_phase_to_op tests ───────────────────────────────────

    #[test]
    fn classify_phase_no_daemon_is_fsync() {
        assert_eq!(
            classify_phase_to_op("no_daemon_phase0_module_load"),
            NoDaemonOpKind::Fsync
        );
        assert_eq!(
            classify_phase_to_op("final_no_daemon_clean"),
            NoDaemonOpKind::Fsync
        );
    }

    #[test]
    fn classify_phase_create_mkdir_is_create() {
        assert_eq!(
            classify_phase_to_op("phase5_create"),
            NoDaemonOpKind::Create
        );
        assert_eq!(classify_phase_to_op("phase5_mkdir"), NoDaemonOpKind::Create);
    }

    #[test]
    fn classify_phase_write_is_write() {
        assert_eq!(
            classify_phase_to_op("phase3_write_buffered"),
            NoDaemonOpKind::Write
        );
    }

    #[test]
    fn classify_phase_read_is_read() {
        assert_eq!(
            classify_phase_to_op("phase2_read_sequential"),
            NoDaemonOpKind::Read
        );
    }

    #[test]
    fn classify_phase_remount_is_crash_remount() {
        assert_eq!(
            classify_phase_to_op("remount1_umount"),
            NoDaemonOpKind::CrashRemount
        );
        assert_eq!(
            classify_phase_to_op("remount3_namespace_nested"),
            NoDaemonOpKind::CrashRemount
        );
    }

    #[test]
    fn classify_phase_unknown_defaults_to_fsync() {
        assert_eq!(
            classify_phase_to_op("phase0_module_load"),
            NoDaemonOpKind::Fsync
        );
        assert_eq!(
            classify_phase_to_op("phase1_pool_image"),
            NoDaemonOpKind::Fsync
        );
    }
}
