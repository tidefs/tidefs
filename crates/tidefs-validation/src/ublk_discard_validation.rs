// ublk block-volume discard / write-zeroes validation schema and artifact guard.
//
// This module defines the validation row types for ublk discard/write-zeroes
// validation and enforces the runtime-artifact-source contract: live-runtime
// default to REFUSAL until a genuine RuntimeArtifactSource is attached.
//
// NONCLAIM: This is a validation schema guard, NOT product runtime validation.
// No QEMU-guest, mounted-kernel, kernel-block-I/O, or no-daemon validation
// is claimed by this module. All live-tier rows are REFUSAL by default.
// Source/cargo tests here are development smoke, not release validation.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::runtime_artifact_source::RuntimeArtifactSource;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DiscardOpKind {
    TrimSingle,
    TrimMulti,
    WriteZeroes,
    TrimWriteRewrite,
    CrashConsistentTrim,
}

impl DiscardOpKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::TrimSingle => "trim-single",
            Self::TrimMulti => "trim-multi",
            Self::WriteZeroes => "write-zeroes",
            Self::TrimWriteRewrite => "trim-write-rewrite",
            Self::CrashConsistentTrim => "crash-consistent-trim",
        }
    }
}

impl fmt::Display for DiscardOpKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum DiscardValidationTier {
    SourceModel,
    CargoUnit,
    SimulatedUserspace,
    LiveHost,
    LiveGuest,
}

impl DiscardValidationTier {
    pub fn label(self) -> &'static str {
        match self {
            Self::SourceModel => "source/model",
            Self::CargoUnit => "cargo/unit",
            Self::SimulatedUserspace => "simulated-userspace",
            Self::LiveHost => "mounted-userspace",
            Self::LiveGuest => "qemu-guest",
        }
    }

    pub fn requires_artifact(self) -> bool {
        matches!(self, Self::LiveHost | Self::LiveGuest)
    }

    /// Map this domain tier to the unified [`crate::validation_schema::ValidationTier`].
    pub fn to_validation_tier(self) -> crate::validation_schema::ValidationTier {
        match self {
            Self::SourceModel => crate::validation_schema::ValidationTier::SourceModel,
            Self::CargoUnit => crate::validation_schema::ValidationTier::CargoUnit,
            Self::SimulatedUserspace => crate::validation_schema::ValidationTier::HarnessOnly,
            Self::LiveHost => crate::validation_schema::ValidationTier::MountedUserspace,
            Self::LiveGuest => crate::validation_schema::ValidationTier::QemuGuest,
        }
    }
}

impl fmt::Display for DiscardValidationTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.label())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DiscardOutcome {
    Pass,
    Fail,
    Refusal,
}

impl fmt::Display for DiscardOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail => write!(f, "FAIL"),
            Self::Refusal => write!(f, "REFUSAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscardValidationRow {
    pub tier: DiscardValidationTier,
    /// Unified validation tier (T0-T7) derived from domain tier.
    pub unified_tier: crate::validation_schema::ValidationTier,
    pub op_kind: DiscardOpKind,
    pub outcome: DiscardOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refusal_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact: Option<RuntimeArtifactSource>,
}

impl DiscardValidationRow {
    pub fn pass(tier: DiscardValidationTier, op_kind: DiscardOpKind) -> Self {
        let unified_tier = tier.to_validation_tier();
        if !tier.requires_artifact() {
            Self {
                tier,
                unified_tier,
                op_kind,
                outcome: DiscardOutcome::Pass,
                refusal_reason: None,
                artifact: None,
            }
        } else {
            Self {
                tier,
                unified_tier,
                op_kind,
                outcome: DiscardOutcome::Refusal,
                refusal_reason: Some(
                    "live-runtime tier BLOCKED -- not run without RuntimeArtifactSource; use pass_with_artifact()"
                        .to_string(),
                ),
                artifact: None,
            }
        }
    }

    pub fn pass_with_artifact(
        tier: DiscardValidationTier,
        op_kind: DiscardOpKind,
        artifact: RuntimeArtifactSource,
    ) -> Self {
        let unified_tier = tier.to_validation_tier();
        let genuine = artifact.is_genuine();
        Self {
            tier,
            unified_tier,
            op_kind,
            outcome: if genuine {
                DiscardOutcome::Pass
            } else {
                DiscardOutcome::Refusal
            },
            refusal_reason: if genuine {
                None
            } else {
                Some("artifact not genuine".into())
            },
            artifact: Some(artifact),
        }
    }

    pub fn refusal(tier: DiscardValidationTier, op_kind: DiscardOpKind, reason: &str) -> Self {
        let unified_tier = tier.to_validation_tier();
        Self {
            tier,
            unified_tier,
            op_kind,
            outcome: DiscardOutcome::Refusal,
            refusal_reason: Some(reason.to_string()),
            artifact: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genuine_artifact() -> RuntimeArtifactSource {
        RuntimeArtifactSource {
            command: "./run-qemu-ublk-discard.sh".into(),
            environment: "Linux 7.0 QEMU guest, x86_64".into(),
            commit: "deadbeefcafebabe".into(),
            kernel_version: Some("7.0.0-tidefs+".into()),
            exit_status: 0,
            stdout_path: Some("/tmp/ublk-discard-stdout.log".into()),
            stderr_path: Some("/tmp/ublk-discard-stderr.log".into()),
            workload_ran: true,
        }
    }

    fn non_genuine_empty_command() -> RuntimeArtifactSource {
        RuntimeArtifactSource {
            command: "".into(),
            environment: "".into(),
            commit: "abc".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: true,
        }
    }

    fn non_genuine_not_ran() -> RuntimeArtifactSource {
        RuntimeArtifactSource {
            command: "./run-test.sh".into(),
            environment: "".into(),
            commit: "abc".into(),
            kernel_version: None,
            exit_status: 0,
            stdout_path: None,
            stderr_path: None,
            workload_ran: false,
        }
    }

    #[test]
    fn pass_refuses_live_host() {
        let row =
            DiscardValidationRow::pass(DiscardValidationTier::LiveHost, DiscardOpKind::TrimSingle);
        assert_eq!(row.outcome, DiscardOutcome::Refusal);
        assert!(row.refusal_reason.is_some());
        assert!(row.artifact.is_none());
    }

    #[test]
    fn pass_refuses_live_guest() {
        let row =
            DiscardValidationRow::pass(DiscardValidationTier::LiveGuest, DiscardOpKind::WriteZeroes);
        assert_eq!(row.outcome, DiscardOutcome::Refusal);
        assert!(row.refusal_reason.is_some());
        assert!(row.artifact.is_none());
    }

    #[test]
    fn pass_refuses_all_live_runtime_tiers_across_all_ops() {
        for tier in [
            DiscardValidationTier::LiveHost,
            DiscardValidationTier::LiveGuest,
        ] {
            for op in [
                DiscardOpKind::TrimSingle,
                DiscardOpKind::TrimMulti,
                DiscardOpKind::WriteZeroes,
                DiscardOpKind::TrimWriteRewrite,
                DiscardOpKind::CrashConsistentTrim,
            ] {
                let row = DiscardValidationRow::pass(tier, op);
                assert_eq!(
                    row.outcome,
                    DiscardOutcome::Refusal,
                    "pass({tier:?}, {op:?}) expected REFUSAL"
                );
            }
        }
    }

    #[test]
    fn pass_allows_source_model() {
        let row =
            DiscardValidationRow::pass(DiscardValidationTier::SourceModel, DiscardOpKind::TrimSingle);
        assert_eq!(row.outcome, DiscardOutcome::Pass);
        assert!(row.refusal_reason.is_none());
        assert!(row.artifact.is_none());
    }

    #[test]
    fn pass_allows_cargo_unit() {
        let row =
            DiscardValidationRow::pass(DiscardValidationTier::CargoUnit, DiscardOpKind::WriteZeroes);
        assert_eq!(row.outcome, DiscardOutcome::Pass);
    }

    #[test]
    fn pass_allows_simulated_userspace() {
        let row = DiscardValidationRow::pass(
            DiscardValidationTier::SimulatedUserspace,
            DiscardOpKind::TrimWriteRewrite,
        );
        assert_eq!(row.outcome, DiscardOutcome::Pass);
    }

    #[test]
    fn pass_with_artifact_genuine_yields_pass() {
        let row = DiscardValidationRow::pass_with_artifact(
            DiscardValidationTier::LiveHost,
            DiscardOpKind::TrimSingle,
            genuine_artifact(),
        );
        assert_eq!(row.outcome, DiscardOutcome::Pass);
        assert!(row.refusal_reason.is_none());
        assert!(row.artifact.is_some());
        assert!(row.artifact.as_ref().unwrap().is_genuine());
    }

    #[test]
    fn pass_with_artifact_empty_command_yields_refusal() {
        let row = DiscardValidationRow::pass_with_artifact(
            DiscardValidationTier::LiveGuest,
            DiscardOpKind::TrimMulti,
            non_genuine_empty_command(),
        );
        assert_eq!(row.outcome, DiscardOutcome::Refusal);
        assert!(row.refusal_reason.is_some());
    }

    #[test]
    fn pass_with_artifact_not_ran_yields_refusal() {
        let row = DiscardValidationRow::pass_with_artifact(
            DiscardValidationTier::LiveGuest,
            DiscardOpKind::CrashConsistentTrim,
            non_genuine_not_ran(),
        );
        assert_eq!(row.outcome, DiscardOutcome::Refusal);
        assert!(row.refusal_reason.is_some());
    }

    #[test]
    fn pass_with_artifact_gates_all_discard_ops() {
        for tier in [
            DiscardValidationTier::LiveHost,
            DiscardValidationTier::LiveGuest,
        ] {
            for op in [
                DiscardOpKind::TrimSingle,
                DiscardOpKind::TrimMulti,
                DiscardOpKind::WriteZeroes,
                DiscardOpKind::TrimWriteRewrite,
                DiscardOpKind::CrashConsistentTrim,
            ] {
                let good = DiscardValidationRow::pass_with_artifact(tier, op, genuine_artifact());
                assert_eq!(
                    good.outcome,
                    DiscardOutcome::Pass,
                    "genuine artifact should PASS for {tier:?}/{op:?}"
                );
                let bad = DiscardValidationRow::pass_with_artifact(tier, op, non_genuine_not_ran());
                assert_eq!(
                    bad.outcome,
                    DiscardOutcome::Refusal,
                    "non-genuine artifact should REFUSE for {tier:?}/{op:?}"
                );
            }
        }
    }

    #[test]
    fn row_json_roundtrip_pass() {
        let row = DiscardValidationRow::pass_with_artifact(
            DiscardValidationTier::LiveGuest,
            DiscardOpKind::WriteZeroes,
            genuine_artifact(),
        );
        let json = serde_json::to_string(&row).unwrap();
        let back: DiscardValidationRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, DiscardOutcome::Pass);
        assert_eq!(back.tier, DiscardValidationTier::LiveGuest);
        assert_eq!(back.op_kind, DiscardOpKind::WriteZeroes);
        assert!(back.artifact.is_some());
    }

    #[test]
    fn row_json_roundtrip_refusal() {
        let row =
            DiscardValidationRow::pass(DiscardValidationTier::LiveGuest, DiscardOpKind::TrimSingle);
        assert_eq!(row.outcome, DiscardOutcome::Refusal);
        let json = serde_json::to_string(&row).unwrap();
        let back: DiscardValidationRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, DiscardOutcome::Refusal);
        assert_eq!(back.tier, DiscardValidationTier::LiveGuest);
        assert!(back.artifact.is_none());
    }

    #[test]
    fn source_model_does_not_require_artifact() {
        assert!(!DiscardValidationTier::SourceModel.requires_artifact());
    }

    #[test]
    fn cargo_unit_does_not_require_artifact() {
        assert!(!DiscardValidationTier::CargoUnit.requires_artifact());
    }

    #[test]
    fn simulated_userspace_does_not_require_artifact() {
        assert!(!DiscardValidationTier::SimulatedUserspace.requires_artifact());
    }

    #[test]
    fn live_host_requires_artifact() {
        assert!(DiscardValidationTier::LiveHost.requires_artifact());
    }

    #[test]
    fn live_guest_requires_artifact() {
        assert!(DiscardValidationTier::LiveGuest.requires_artifact());
    }
}
