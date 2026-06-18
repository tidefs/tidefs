// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! ublk discard/write-zeroes artifact-schema regression tests.
//!
//! This test file proves the DiscardValidationRow contract from
//! tidefs_validation::ublk_discard_validation:
//!
//! 1. pass() refuses live-runtime tiers (LiveHost, LiveGuest).
//! 2. pass() allows code-only tiers (SourceModel, CargoUnit, SimulatedUserspace).
//! 3. pass_with_artifact() gates PASS on a genuine RuntimeArtifactSource.
//! 4. Non-genuine artifacts (empty command, workload_ran=false) produce REFUSAL.
//!
//! These are schema/contract guard tests, not runtime validation.

use tidefs_validation::runtime_artifact_source::RuntimeArtifactSource;
use tidefs_validation::ublk_discard_validation::{
    DiscardOpKind, DiscardOutcome, DiscardValidationRow, DiscardValidationTier,
};

fn genuine_artifact() -> RuntimeArtifactSource {
    RuntimeArtifactSource {
        command: "./nix/vm/ublk-discard-validation.nix --run".into(),
        environment: "Linux 7.0 QEMU guest, x86_64".into(),
        commit: "deadbeefcafebabe".into(),
        kernel_version: Some("7.0.0-tidefs+".into()),
        exit_status: 0,
        stdout_path: Some("/tmp/ublk-discard-validation-stdout.log".into()),
        stderr_path: Some("/tmp/ublk-discard-validation-stderr.log".into()),
        workload_ran: true,
    }
}

fn non_genuine_no_command() -> RuntimeArtifactSource {
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
        command: "./test.sh".into(),
        environment: "".into(),
        commit: "abc".into(),
        kernel_version: None,
        exit_status: 0,
        stdout_path: None,
        stderr_path: None,
        workload_ran: false,
    }
}

// ── pass() refuses live-runtime tiers ──────────────────────────────────

#[test]
fn pass_refuses_live_host_for_all_ops() {
    for op in [
        DiscardOpKind::TrimSingle,
        DiscardOpKind::TrimMulti,
        DiscardOpKind::WriteZeroes,
        DiscardOpKind::TrimWriteRewrite,
        DiscardOpKind::CrashConsistentTrim,
    ] {
        let row = DiscardValidationRow::pass(DiscardValidationTier::LiveHost, op);
        assert_eq!(
            row.outcome,
            DiscardOutcome::Refusal,
            "pass(LiveHost, {op:?}) must be REFUSAL"
        );
        assert!(row.refusal_reason.is_some());
        assert!(row.artifact.is_none());
    }
}

#[test]
fn pass_refuses_live_guest_for_all_ops() {
    for op in [
        DiscardOpKind::TrimSingle,
        DiscardOpKind::TrimMulti,
        DiscardOpKind::WriteZeroes,
        DiscardOpKind::TrimWriteRewrite,
        DiscardOpKind::CrashConsistentTrim,
    ] {
        let row = DiscardValidationRow::pass(DiscardValidationTier::LiveGuest, op);
        assert_eq!(
            row.outcome,
            DiscardOutcome::Refusal,
            "pass(LiveGuest, {op:?}) must be REFUSAL"
        );
        assert!(row.artifact.is_none());
    }
}

// ── pass() allows code-only tiers ──────────────────────────────────────

#[test]
fn pass_allows_all_code_only_tiers_across_all_ops() {
    for tier in [
        DiscardValidationTier::SourceModel,
        DiscardValidationTier::CargoUnit,
        DiscardValidationTier::SimulatedUserspace,
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
                DiscardOutcome::Pass,
                "pass({tier:?}, {op:?}) must PASS for code-only tier"
            );
            assert!(row.artifact.is_none());
        }
    }
}

// ── pass_with_artifact gates on genuine artifact ───────────────────────

#[test]
fn pass_with_artifact_genuine_yields_pass_for_all_live_tiers_and_ops() {
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
            let row = DiscardValidationRow::pass_with_artifact(tier, op, genuine_artifact());
            assert_eq!(
                row.outcome,
                DiscardOutcome::Pass,
                "genuine artifact must PASS for {tier:?}/{op:?}"
            );
            assert!(row.refusal_reason.is_none());
            assert!(row.artifact.is_some());
        }
    }
}

#[test]
fn pass_with_artifact_empty_command_refused_for_all_live_tiers_and_ops() {
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
            let row = DiscardValidationRow::pass_with_artifact(tier, op, non_genuine_no_command());
            assert_eq!(
                row.outcome,
                DiscardOutcome::Refusal,
                "empty-command artifact must REFUSE for {tier:?}/{op:?}"
            );
        }
    }
}

#[test]
fn pass_with_artifact_not_ran_refused_for_all_live_tiers_and_ops() {
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
            let row = DiscardValidationRow::pass_with_artifact(tier, op, non_genuine_not_ran());
            assert_eq!(
                row.outcome,
                DiscardOutcome::Refusal,
                "workload_ran=false artifact must REFUSE for {tier:?}/{op:?}"
            );
        }
    }
}

// ── JSON round-trip preserves artifact metadata ────────────────────────

#[test]
fn json_roundtrip_preserves_artifact_fields() {
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
    let artifact = back.artifact.expect("artifact must round-trip");
    assert!(artifact.is_genuine());
    assert!(!artifact.command.is_empty());
    assert_eq!(artifact.kernel_version.as_deref(), Some("7.0.0-tidefs+"));
}
