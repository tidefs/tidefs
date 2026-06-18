// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Unified validation schema for runtime tiers.
//!
//! This module provides the canonical `ValidationTier` enum,
//! `ValidationRow` records, and `ValidationBackend` classification. Validation
//! output is ephemeral operator/runtime output, not repository authority.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::validation_status::ValidationStatus;

/// Unified validation tier covering release-oriented tiers T0-T7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationTier {
    /// Tier 0: source/model/schema/proposal state only.
    SourceModel,
    /// Tier 1: cargo/unit/focused crate tests.
    CargoUnit,
    /// Tier 2: harness without a mounted/live product path.
    HarnessOnly,
    /// Tier 3: mounted userspace runtime.
    MountedUserspace,
    /// Tier 3: QEMU guest runtime.
    QemuGuest,
    /// Tier 4: Linux 7.0 Kbuild compilation.
    Kbuild,
    /// Tier 4: QEMU module load.
    QemuModuleLoad,
    /// Tier 5: mounted kernel VFS.
    MountedKernelVfs,
    /// Tier 5: kernel block I/O.
    KernelBlockIo,
    /// Tier 6: full-kernel no-daemon mounted operation.
    FullKernelNoDaemon,
    /// Tier 7: multi-process distributed/RDMA runtime.
    MultiProcessDistributed,
}

impl ValidationTier {
    /// Numeric tier level (0-7).
    pub fn tier_level(&self) -> u8 {
        match self {
            ValidationTier::SourceModel => 0,
            ValidationTier::CargoUnit => 1,
            ValidationTier::HarnessOnly => 2,
            ValidationTier::MountedUserspace | ValidationTier::QemuGuest => 3,
            ValidationTier::Kbuild | ValidationTier::QemuModuleLoad => 4,
            ValidationTier::MountedKernelVfs | ValidationTier::KernelBlockIo => 5,
            ValidationTier::FullKernelNoDaemon => 6,
            ValidationTier::MultiProcessDistributed => 7,
        }
    }

    /// Human-readable label for display and serialization.
    pub fn label(&self) -> &'static str {
        match self {
            ValidationTier::SourceModel => "source-model",
            ValidationTier::CargoUnit => "cargo-unit",
            ValidationTier::HarnessOnly => "harness-only",
            ValidationTier::MountedUserspace => "mounted-userspace",
            ValidationTier::QemuGuest => "qemu-guest",
            ValidationTier::MultiProcessDistributed => "multi-process-distributed",
            ValidationTier::Kbuild => "kbuild",
            ValidationTier::QemuModuleLoad => "qemu-module-load",
            ValidationTier::MountedKernelVfs => "mounted-kernel-vfs",
            ValidationTier::KernelBlockIo => "kernel-block-io",
            ValidationTier::FullKernelNoDaemon => "full-kernel-no-daemon",
        }
    }

    /// True for tiers that represent runtime execution or kernel integration.
    pub fn is_runtime(&self) -> bool {
        matches!(
            self,
            ValidationTier::MountedUserspace
                | ValidationTier::QemuGuest
                | ValidationTier::MultiProcessDistributed
                | ValidationTier::Kbuild
                | ValidationTier::QemuModuleLoad
                | ValidationTier::MountedKernelVfs
                | ValidationTier::KernelBlockIo
                | ValidationTier::FullKernelNoDaemon
        )
    }

    /// True for live-runtime tiers suitable for release gate closure.
    pub fn is_live_runtime(&self) -> bool {
        matches!(
            self,
            ValidationTier::MountedUserspace
                | ValidationTier::QemuGuest
                | ValidationTier::MultiProcessDistributed
                | ValidationTier::QemuModuleLoad
                | ValidationTier::MountedKernelVfs
                | ValidationTier::KernelBlockIo
                | ValidationTier::FullKernelNoDaemon
        )
    }

    /// True when this tier represents code-only validation.
    pub fn is_code_only(&self) -> bool {
        matches!(self, ValidationTier::Kbuild)
    }

    /// True when this tier requires a QEMU guest process.
    pub fn requires_qemu(&self) -> bool {
        matches!(
            self,
            ValidationTier::QemuGuest
                | ValidationTier::QemuModuleLoad
                | ValidationTier::MountedKernelVfs
                | ValidationTier::KernelBlockIo
                | ValidationTier::FullKernelNoDaemon
        )
    }

    /// Terminal tier needed for full multi-process/distributed validation.
    pub fn terminal_tier() -> Self {
        ValidationTier::MultiProcessDistributed
    }
}

impl fmt::Display for ValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// Storage or transport backend used by a validation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationBackend {
    /// File backend on a local filesystem.
    File,
    /// Local object store backend.
    LocalObjectStore,
    /// Block device backend.
    Block,
    /// TCP transport carrier.
    Tcp,
    /// RDMA transport carrier.
    Rdma,
    /// Loopback transport.
    Loopback,
    /// Deterministic in-memory backend.
    DeterministicInMemory,
    /// Backend not applicable.
    #[default]
    NotApplicable,
}

impl ValidationBackend {
    pub fn label(&self) -> &'static str {
        match self {
            ValidationBackend::File => "file",
            ValidationBackend::LocalObjectStore => "local-object-store",
            ValidationBackend::Block => "block",
            ValidationBackend::Tcp => "tcp",
            ValidationBackend::Rdma => "rdma",
            ValidationBackend::Loopback => "loopback",
            ValidationBackend::DeterministicInMemory => "deterministic-in-memory",
            ValidationBackend::NotApplicable => "not-applicable",
        }
    }
}

impl fmt::Display for ValidationBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A single validation row with stable required fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationRow {
    /// Validation tier (T0-T7).
    pub tier: ValidationTier,
    /// Full command line that produced the output.
    pub command: String,
    /// Output path, when a run wrote one.
    pub output: String,
    /// Repository commit SHA at collection time, when known.
    pub commit: String,
    /// Storage or transport backend used.
    pub backend: ValidationBackend,
    /// Outcome: pass, product-fail, harness-fail, environment-refusal, or skip.
    pub result: ValidationStatus,
    /// Optional description of what was validated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Kernel version string for kernel-tier validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,
    /// Process exit status (0 = success).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_status: Option<i32>,
    /// Branch name at collection time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// UTC ISO 8601 timestamp when validation was run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collected_at: Option<String>,
}

impl ValidationRow {
    /// Create a new validation row with the required fields.
    pub fn new(
        tier: ValidationTier,
        command: impl Into<String>,
        output: impl Into<String>,
        commit: impl Into<String>,
        backend: ValidationBackend,
        result: ValidationStatus,
    ) -> Self {
        ValidationRow {
            tier,
            command: command.into(),
            output: output.into(),
            commit: commit.into(),
            backend,
            result,
            description: None,
            kernel_version: None,
            exit_status: None,
            branch: None,
            collected_at: None,
        }
    }

    /// True when this row represents a passing live-runtime execution.
    pub fn is_live_runtime_pass(&self) -> bool {
        self.tier.is_live_runtime() && self.result == ValidationStatus::Pass
    }

    /// True when this row can close a release gate.
    pub fn can_close_gate(&self) -> bool {
        self.is_live_runtime_pass() && !self.output.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_levels_match_release_focus() {
        assert_eq!(ValidationTier::SourceModel.tier_level(), 0);
        assert_eq!(ValidationTier::CargoUnit.tier_level(), 1);
        assert_eq!(ValidationTier::HarnessOnly.tier_level(), 2);
        assert_eq!(ValidationTier::MountedUserspace.tier_level(), 3);
        assert_eq!(ValidationTier::QemuGuest.tier_level(), 3);
        assert_eq!(ValidationTier::Kbuild.tier_level(), 4);
        assert_eq!(ValidationTier::QemuModuleLoad.tier_level(), 4);
        assert_eq!(ValidationTier::MountedKernelVfs.tier_level(), 5);
        assert_eq!(ValidationTier::KernelBlockIo.tier_level(), 5);
        assert_eq!(ValidationTier::FullKernelNoDaemon.tier_level(), 6);
        assert_eq!(ValidationTier::MultiProcessDistributed.tier_level(), 7);
    }

    #[test]
    fn validation_row_new() {
        let row = ValidationRow::new(
            ValidationTier::QemuGuest,
            "nix run .#qemu-smoke",
            "/root/ai/tmp/tidefs-validation/qemu-smoke/output.log",
            "abc123def",
            ValidationBackend::File,
            ValidationStatus::Pass,
        );
        assert_eq!(row.tier, ValidationTier::QemuGuest);
        assert_eq!(row.result, ValidationStatus::Pass);
        assert!(row.is_live_runtime_pass());
        assert!(row.can_close_gate());
    }
}
