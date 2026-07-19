// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Structured validation for mounted storage-intent acknowledgment evidence.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt;

use serde::Deserialize;

use crate::evidence_artifact_manifest::{
    content_digest_for_bytes, parse_evidence_artifact_manifest_json,
};
use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;

pub const ACK_RUNTIME_REPORT_VERSION: u32 = 1;
pub const ACK_RUNTIME_CLAIM_ID: &str = "storage.intent.ack_receipt_honesty.v1";
pub const ACK_RUNTIME_EVIDENCE_CLASS: &str = "storage-intent-ack-receipt-runtime";
pub const ACK_RUNTIME_ARTIFACT_PATH: &str =
    "validation/artifacts/storage-intent/ack-receipt-runtime.json";
pub const ACK_RUNTIME_MANIFEST_PATH: &str =
    "validation/artifacts/storage-intent/ack-receipt-runtime.manifest.json";
pub const ACK_RUNTIME_SOURCE: &str = "mounted-fuse-ack-receipt-runtime-v1";
pub const ACK_RUNTIME_ISSUE_URL: &str = "https://github.com/tidefs/tidefs/issues/2223";
pub const ACK_RUNTIME_PARENT_ISSUE_URL: &str = "https://github.com/tidefs/tidefs/issues/1794";
pub const ACK_RUNTIME_REPORT_FILE: &str = "ack-receipt-runtime.json";
pub const ACK_RUNTIME_MANIFEST_FILE: &str = "ack-receipt-runtime.manifest.json";
pub const ACK_RUNTIME_COMMAND: &str = "storage-intent-ack-runtime-validation";
pub const ACK_RUNTIME_RECEIPT_SOURCE: &str = "bounded LocalAckReceiptLedger diagnostic copies";
pub const ACK_RUNTIME_BLOCKING_ISSUE: u64 = 2223;
pub const ACK_RUNTIME_BLOCKING_REASON: &str =
    "mounted acknowledgment runtime rows have not all earned their exact receipt or explicit refusal";
pub const ACK_RUNTIME_LIVE_BACKEND_KIND: &str = "live-fuse-local-object-store";
pub const ACK_RUNTIME_REFUSED_BACKEND_KIND: &str = "fuse-mount-environment-refused";
pub const ACK_RUNTIME_MOUNT_OPTIONS: [&str; 4] = ["rw", "nodev", "nosuid", "subtype=tidefs"];

const LOCAL_INTENT_EVIDENCE_REF_COUNT: usize = 9;
const FULL_PLACEMENT_EVIDENCE_REF_COUNT: usize = 10;

#[derive(Clone, Copy)]
struct ExpectedRow {
    row_id: &'static str,
    syscall: &'static str,
    receipt_operation: &'static str,
    refusal_allowed: bool,
}

const EXPECTED_ROWS: &[ExpectedRow] = &[
    ExpectedRow {
        row_id: "sync-write-receipt",
        syscall: "write(O_SYNC)",
        receipt_operation: "sync-write",
        refusal_allowed: false,
    },
    ExpectedRow {
        row_id: "fsync-receipt",
        syscall: "fsync",
        receipt_operation: "fsync",
        refusal_allowed: false,
    },
    ExpectedRow {
        row_id: "fdatasync-receipt",
        syscall: "fdatasync",
        receipt_operation: "fdatasync",
        refusal_allowed: false,
    },
    ExpectedRow {
        row_id: "odsync-receipt",
        syscall: "write(O_DSYNC)",
        receipt_operation: "odsync",
        refusal_allowed: false,
    },
    ExpectedRow {
        row_id: "shared-mmap-msync-receipt-or-refusal",
        syscall: "mmap(MAP_SHARED)+msync(MS_SYNC)",
        receipt_operation: "shared-mmap-msync",
        refusal_allowed: true,
    },
    ExpectedRow {
        row_id: "namespace-receipt",
        syscall: "create+rename+fsync(parent)",
        receipt_operation: "fsync-directory",
        refusal_allowed: false,
    },
    ExpectedRow {
        row_id: "fsyncdir-receipt",
        syscall: "fsyncdir",
        receipt_operation: "fsync-directory",
        refusal_allowed: false,
    },
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeReport {
    report_version: u32,
    claim_id: String,
    issue: String,
    parent_issue: String,
    run_id: String,
    source_ref: String,
    generated_at: String,
    validation_tier: ValidationTier,
    command: String,
    backend: RuntimeBackend,
    rows: Vec<RuntimeRow>,
    summary: RuntimeSummary,
    residual_risk: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBackend {
    kind: String,
    carrier: String,
    kernel_release: String,
    mount_options: Vec<String>,
    receipt_source: String,
    fault_injection: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeRow {
    row_id: String,
    syscall: String,
    expected_receipt_operation: String,
    syscall_result: String,
    errno: Option<i32>,
    observed_receipts: Vec<ReceiptObservation>,
    outcome: ValidationStatus,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptObservation {
    operation: String,
    requested_ack_floor: String,
    earned_ack_class: String,
    disposition: String,
    convergence: String,
    durability_state: String,
    target_inode: Option<u64>,
    target_offset: u64,
    target_length: u64,
    target_has_range: bool,
    evidence_ref_count: usize,
    refusal_reason: String,
    posix_durable_success: bool,
    satisfies_requested_ack_floor: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeSummary {
    status: ValidationStatus,
    passed: usize,
    product_failed: usize,
    harness_failed: usize,
    environment_refused: usize,
    skipped: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AckRuntimeEvidenceError {
    failures: Vec<String>,
}

impl AckRuntimeEvidenceError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }

    fn single(failure: impl Into<String>) -> Self {
        Self {
            failures: vec![failure.into()],
        }
    }

    fn from_failures(failures: Vec<String>) -> Result<(), Self> {
        if failures.is_empty() {
            Ok(())
        } else {
            Err(Self { failures })
        }
    }
}

impl fmt::Display for AckRuntimeEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "mounted acknowledgment runtime evidence validation failed:"
        )?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for AckRuntimeEvidenceError {}

#[must_use]
pub fn ack_runtime_manifest_scope(
    status: ValidationStatus,
    passed: usize,
    product_failed: usize,
    environment_refused: usize,
) -> String {
    format!(
        "live FUSE mounted acknowledgment receipt and refusal rows for write, fsync, fdatasync, O_DSYNC, shared mmap MS_SYNC, namespace mutation, and fsyncdir; outcome={} pass={passed} product_fail={product_failed} environment_refusal={environment_refused}",
        status.label()
    )
}

pub fn validate_ack_runtime_report_json(report_json: &[u8]) -> Result<(), AckRuntimeEvidenceError> {
    parse_and_validate_report(report_json).map(|_| ())
}

pub fn validate_ack_runtime_evidence_json(
    report_json: &[u8],
    manifest_json: &[u8],
) -> Result<(), AckRuntimeEvidenceError> {
    let report = parse_and_validate_report(report_json)?;
    let manifest_text = std::str::from_utf8(manifest_json).map_err(|error| {
        AckRuntimeEvidenceError::single(format!("manifest is not UTF-8 JSON: {error}"))
    })?;
    let manifest = parse_evidence_artifact_manifest_json(manifest_text).map_err(|error| {
        AckRuntimeEvidenceError::single(format!("generic evidence manifest is invalid: {error}"))
    })?;
    let mut failures = Vec::new();

    check_equal(
        "manifest claim_id",
        &manifest.claim_id,
        ACK_RUNTIME_CLAIM_ID,
        &mut failures,
    );
    check_equal(
        "manifest evidence_class",
        &manifest.evidence_class,
        ACK_RUNTIME_EVIDENCE_CLASS,
        &mut failures,
    );
    if manifest.validation_tier != report.validation_tier {
        failures.push(format!(
            "manifest validation_tier {:?} does not match report {:?}",
            manifest.validation_tier, report.validation_tier
        ));
    }
    check_equal(
        "manifest artifact_path",
        &manifest.artifact_path,
        ACK_RUNTIME_ARTIFACT_PATH,
        &mut failures,
    );
    let expected_digest = content_digest_for_bytes(report_json);
    check_equal(
        "manifest content_digest",
        &manifest.content_digest,
        &expected_digest,
        &mut failures,
    );
    check_equal(
        "manifest run_id",
        &manifest.run_id,
        &report.run_id,
        &mut failures,
    );
    check_equal(
        "manifest source_ref",
        &manifest.source_ref,
        &report.source_ref,
        &mut failures,
    );
    if manifest.outcome != report.summary.status {
        failures.push(format!(
            "manifest outcome {:?} does not match report summary {:?}",
            manifest.outcome, report.summary.status
        ));
    }
    check_equal(
        "manifest generated_at",
        &manifest.generated_at,
        &report.generated_at,
        &mut failures,
    );
    check_equal(
        "manifest source",
        &manifest.source,
        ACK_RUNTIME_SOURCE,
        &mut failures,
    );
    let expected_residual_risk = report.residual_risk.join(" ");
    check_equal(
        "manifest residual_risk",
        &manifest.residual_risk,
        &expected_residual_risk,
        &mut failures,
    );
    let expected_scope = ack_runtime_manifest_scope(
        report.summary.status,
        report.summary.passed,
        report.summary.product_failed,
        report.summary.environment_refused,
    );
    check_equal(
        "manifest scope",
        &manifest.scope,
        &expected_scope,
        &mut failures,
    );

    if report.summary.status == ValidationStatus::Pass {
        if !manifest.blocking_issues.is_empty() {
            failures.push("pass report must not retain blocking_issues".to_string());
        }
    } else if manifest.blocking_issues.len() != 1 {
        failures.push(format!(
            "non-pass report must name only issue #{ACK_RUNTIME_BLOCKING_ISSUE} as its blocker, found {} entries",
            manifest.blocking_issues.len()
        ));
    } else {
        let issue = &manifest.blocking_issues[0];
        if issue.number != ACK_RUNTIME_BLOCKING_ISSUE {
            failures.push(format!(
                "non-pass report blocker must be issue #{ACK_RUNTIME_BLOCKING_ISSUE}, found #{}",
                issue.number
            ));
        }
        if issue.repo.as_deref() != Some("tidefs/tidefs") {
            failures
                .push("non-pass report blocker must name repository `tidefs/tidefs`".to_string());
        }
        if issue.reason.as_deref() != Some(ACK_RUNTIME_BLOCKING_REASON) {
            failures.push(format!(
                "non-pass report blocker reason must be `{ACK_RUNTIME_BLOCKING_REASON}`"
            ));
        }
    }

    AckRuntimeEvidenceError::from_failures(failures)
}

fn parse_and_validate_report(report_json: &[u8]) -> Result<RuntimeReport, AckRuntimeEvidenceError> {
    let report = serde_json::from_slice::<RuntimeReport>(report_json).map_err(|error| {
        AckRuntimeEvidenceError::single(format!("report JSON does not match schema: {error}"))
    })?;
    let mut failures = Vec::new();

    if report.report_version != ACK_RUNTIME_REPORT_VERSION {
        failures.push(format!(
            "report_version must be {ACK_RUNTIME_REPORT_VERSION}, found {}",
            report.report_version
        ));
    }
    check_equal(
        "claim_id",
        &report.claim_id,
        ACK_RUNTIME_CLAIM_ID,
        &mut failures,
    );
    check_equal("issue", &report.issue, ACK_RUNTIME_ISSUE_URL, &mut failures);
    check_equal(
        "parent_issue",
        &report.parent_issue,
        ACK_RUNTIME_PARENT_ISSUE_URL,
        &mut failures,
    );
    if report.validation_tier != ValidationTier::MountedUserspace {
        failures.push(format!(
            "validation_tier must be mounted-userspace, found {:?}",
            report.validation_tier
        ));
    }
    check_equal(
        "command",
        &report.command,
        ACK_RUNTIME_COMMAND,
        &mut failures,
    );
    check_nonempty("run_id", &report.run_id, &mut failures);
    check_nonempty("source_ref", &report.source_ref, &mut failures);
    check_nonempty("generated_at", &report.generated_at, &mut failures);
    check_runtime_provenance("backend.carrier", &report.backend.carrier, &mut failures);
    check_runtime_provenance(
        "backend.kernel_release",
        &report.backend.kernel_release,
        &mut failures,
    );
    let mount_options = report
        .backend
        .mount_options
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    if mount_options.as_slice() != ACK_RUNTIME_MOUNT_OPTIONS.as_slice() {
        failures.push(format!(
            "backend.mount_options must be {:?}, found {:?}",
            ACK_RUNTIME_MOUNT_OPTIONS, report.backend.mount_options
        ));
    }
    check_equal(
        "backend.receipt_source",
        &report.backend.receipt_source,
        ACK_RUNTIME_RECEIPT_SOURCE,
        &mut failures,
    );
    check_equal(
        "backend.fault_injection",
        &report.backend.fault_injection,
        "none",
        &mut failures,
    );
    if report.residual_risk.is_empty()
        || report
            .residual_risk
            .iter()
            .any(|risk| risk.trim().is_empty())
    {
        failures.push("residual_risk must contain only nonempty entries".to_string());
    }

    validate_rows(&report.rows, &mut failures);
    validate_summary(&report.rows, &report.summary, &mut failures);
    validate_backend_kind(&report.backend, &report.rows, &mut failures);
    AckRuntimeEvidenceError::from_failures(failures)?;
    Ok(report)
}

fn validate_rows(rows: &[RuntimeRow], failures: &mut Vec<String>) {
    if rows.len() != EXPECTED_ROWS.len() {
        failures.push(format!(
            "rows must contain exactly {} issue #2223 entries, found {}",
            EXPECTED_ROWS.len(),
            rows.len()
        ));
    }

    let mut seen = BTreeSet::new();
    for row in rows {
        if !seen.insert(row.row_id.as_str()) {
            failures.push(format!("duplicate row_id `{}`", row.row_id));
        }
        let Some(expected) = EXPECTED_ROWS
            .iter()
            .find(|expected| expected.row_id == row.row_id)
        else {
            failures.push(format!("unexpected row_id `{}`", row.row_id));
            continue;
        };
        check_equal(
            &format!("row `{}` syscall", row.row_id),
            &row.syscall,
            expected.syscall,
            failures,
        );
        check_equal(
            &format!("row `{}` expected_receipt_operation", row.row_id),
            &row.expected_receipt_operation,
            expected.receipt_operation,
            failures,
        );
        if row.reason.trim().is_empty() {
            failures.push(format!("row `{}` reason must not be empty", row.row_id));
        }
        validate_receipts(row, failures);
        validate_row_outcome(row, *expected, failures);
    }

    for expected in EXPECTED_ROWS {
        if !seen.contains(expected.row_id) {
            failures.push(format!("missing row_id `{}`", expected.row_id));
        }
    }
}

fn validate_receipts(row: &RuntimeRow, failures: &mut Vec<String>) {
    for (index, receipt) in row.observed_receipts.iter().enumerate() {
        let prefix = format!("row `{}` receipt {index}", row.row_id);
        for (field, value) in [
            ("operation", receipt.operation.as_str()),
            ("requested_ack_floor", receipt.requested_ack_floor.as_str()),
            ("earned_ack_class", receipt.earned_ack_class.as_str()),
            ("disposition", receipt.disposition.as_str()),
            ("convergence", receipt.convergence.as_str()),
            ("durability_state", receipt.durability_state.as_str()),
            ("refusal_reason", receipt.refusal_reason.as_str()),
        ] {
            if value.trim().is_empty() {
                failures.push(format!("{prefix} {field} must not be empty"));
            }
        }
        if !receipt_has_supported_target_shape(receipt) {
            failures.push(format!(
                "{prefix} target does not match operation `{}`",
                receipt.operation
            ));
        }
        let expected_posix_durable_success = receipt.disposition == "durable-posix"
            && matches!(
                receipt.durability_state.as_str(),
                "DurableIntent" | "FullPlacement"
            );
        if receipt.posix_durable_success != expected_posix_durable_success {
            failures.push(format!(
                "{prefix} posix_durable_success={} contradicts disposition `{}` and durability_state `{}`",
                receipt.posix_durable_success, receipt.disposition, receipt.durability_state
            ));
        }
        if receipt.satisfies_requested_ack_floor && !receipt_has_supported_satisfying_shape(receipt)
        {
            failures.push(format!(
                "{prefix} claims to satisfy the requested floor without a supported durable receipt shape"
            ));
        }
    }
}

fn validate_row_outcome(row: &RuntimeRow, expected: ExpectedRow, failures: &mut Vec<String>) {
    let exact_receipt = row.observed_receipts.iter().any(|receipt| {
        receipt.operation == expected.receipt_operation
            && receipt.satisfies_requested_ack_floor
            && receipt_has_supported_satisfying_shape(receipt)
    });
    let any_satisfying_receipt = row.observed_receipts.iter().any(|receipt| {
        receipt.satisfies_requested_ack_floor && receipt_has_supported_satisfying_shape(receipt)
    });

    match row.outcome {
        ValidationStatus::Pass if row.syscall_result == "success" => {
            if row.errno.is_some() {
                failures.push(format!(
                    "row `{}` successful pass must not record errno",
                    row.row_id
                ));
            }
            if !exact_receipt {
                failures.push(format!(
                    "row `{}` successful pass requires an exact earned `{}` receipt",
                    row.row_id, expected.receipt_operation
                ));
            }
        }
        ValidationStatus::Pass if row.syscall_result == "refused" => {
            if !expected.refusal_allowed {
                failures.push(format!(
                    "row `{}` cannot treat unsupported refusal as pass",
                    row.row_id
                ));
            }
            if !row.errno.is_some_and(is_supported_refusal_errno) {
                failures.push(format!(
                    "row `{}` refusal pass must use an accepted unsupported errno",
                    row.row_id
                ));
            }
            if any_satisfying_receipt {
                failures.push(format!(
                    "row `{}` refusal pass contradicts an observed satisfying receipt",
                    row.row_id
                ));
            }
        }
        ValidationStatus::Pass => failures.push(format!(
            "row `{}` pass uses unsupported syscall_result `{}`",
            row.row_id, row.syscall_result
        )),
        ValidationStatus::ProductFail if row.syscall_result == "success" => {
            if row.errno.is_some() {
                failures.push(format!(
                    "row `{}` successful product-fail must not record errno",
                    row.row_id
                ));
            }
            if exact_receipt {
                failures.push(format!(
                    "row `{}` cannot remain product-fail after observing its exact earned receipt",
                    row.row_id
                ));
            }
        }
        ValidationStatus::ProductFail if row.syscall_result == "error" => {
            if row.errno.is_none() {
                failures.push(format!(
                    "row `{}` error product-fail must record errno",
                    row.row_id
                ));
            }
            if exact_receipt {
                failures.push(format!(
                    "row `{}` error product-fail contradicts its exact earned receipt",
                    row.row_id
                ));
            }
        }
        ValidationStatus::ProductFail => failures.push(format!(
            "row `{}` product-fail uses unsupported syscall_result `{}`",
            row.row_id, row.syscall_result
        )),
        ValidationStatus::EnvironmentRefusal => {
            if row.syscall_result != "environment-refused" {
                failures.push(format!(
                    "row `{}` environment refusal must use syscall_result `environment-refused`",
                    row.row_id
                ));
            }
            if row
                .errno
                .is_some_and(|errno| !is_environment_refusal_errno(errno))
            {
                failures.push(format!(
                    "row `{}` environment refusal uses unexpected errno {:?}",
                    row.row_id, row.errno
                ));
            }
            if !row.observed_receipts.is_empty() {
                failures.push(format!(
                    "row `{}` environment refusal must not contain receipts",
                    row.row_id
                ));
            }
        }
        ValidationStatus::HarnessFail | ValidationStatus::Skip => failures.push(format!(
            "row `{}` uses {:?}, which report_version {} does not encode",
            row.row_id, row.outcome, ACK_RUNTIME_REPORT_VERSION
        )),
    }
}

fn receipt_has_supported_target_shape(receipt: &ReceiptObservation) -> bool {
    let inode_is_bound = receipt.target_inode.is_some_and(|inode| inode != 0);
    match receipt.operation.as_str() {
        "sync-write" | "odsync" | "shared-mmap-msync" => {
            receipt.target_has_range && inode_is_bound && receipt.target_length != 0
        }
        "fsync" | "fdatasync" | "fsync-directory" => {
            !receipt.target_has_range
                && inode_is_bound
                && receipt.target_offset == 0
                && receipt.target_length == 0
        }
        _ => false,
    }
}

fn receipt_has_supported_satisfying_shape(receipt: &ReceiptObservation) -> bool {
    if receipt.requested_ack_floor != "local-intent"
        || receipt.disposition != "durable-posix"
        || receipt.refusal_reason != "None"
        || !receipt.posix_durable_success
        || !receipt_has_supported_target_shape(receipt)
    {
        return false;
    }

    match receipt.earned_ack_class.as_str() {
        "local-intent" => {
            receipt.durability_state == "DurableIntent"
                && matches!(
                    receipt.convergence.as_str(),
                    "satisfied" | "pending-full-placement" | "converging"
                )
                && receipt.evidence_ref_count == LOCAL_INTENT_EVIDENCE_REF_COUNT
        }
        "full-placement" => {
            receipt.durability_state == "FullPlacement"
                && receipt.convergence == "satisfied"
                && receipt.evidence_ref_count == FULL_PLACEMENT_EVIDENCE_REF_COUNT
        }
        _ => false,
    }
}

fn validate_summary(rows: &[RuntimeRow], summary: &RuntimeSummary, failures: &mut Vec<String>) {
    let count = |status| rows.iter().filter(|row| row.outcome == status).count();
    let expected_passed = count(ValidationStatus::Pass);
    let expected_product_failed = count(ValidationStatus::ProductFail);
    let expected_harness_failed = count(ValidationStatus::HarnessFail);
    let expected_environment_refused = count(ValidationStatus::EnvironmentRefusal);
    let expected_skipped = count(ValidationStatus::Skip);
    for (field, actual, expected) in [
        ("passed", summary.passed, expected_passed),
        (
            "product_failed",
            summary.product_failed,
            expected_product_failed,
        ),
        (
            "harness_failed",
            summary.harness_failed,
            expected_harness_failed,
        ),
        (
            "environment_refused",
            summary.environment_refused,
            expected_environment_refused,
        ),
        ("skipped", summary.skipped, expected_skipped),
    ] {
        if actual != expected {
            failures.push(format!(
                "summary.{field} is {actual}, recomputed row count is {expected}"
            ));
        }
    }
    let expected_status = if expected_harness_failed > 0 {
        ValidationStatus::HarnessFail
    } else if expected_product_failed > 0 {
        ValidationStatus::ProductFail
    } else if expected_environment_refused > 0 {
        ValidationStatus::EnvironmentRefusal
    } else if expected_skipped > 0 {
        ValidationStatus::Skip
    } else {
        ValidationStatus::Pass
    };
    if summary.status != expected_status {
        failures.push(format!(
            "summary.status {:?} does not match recomputed {:?}",
            summary.status, expected_status
        ));
    }
    if expected_environment_refused > 0 && expected_environment_refused != rows.len() {
        failures.push(
            "mount environment refusal must classify all seven rows as environment-refused"
                .to_string(),
        );
    }
}

fn validate_backend_kind(
    backend: &RuntimeBackend,
    rows: &[RuntimeRow],
    failures: &mut Vec<String>,
) {
    let all_environment_refused = !rows.is_empty()
        && rows
            .iter()
            .all(|row| row.outcome == ValidationStatus::EnvironmentRefusal);
    let expected_kind = if all_environment_refused {
        ACK_RUNTIME_REFUSED_BACKEND_KIND
    } else {
        ACK_RUNTIME_LIVE_BACKEND_KIND
    };
    check_equal("backend.kind", &backend.kind, expected_kind, failures);
}

fn is_supported_refusal_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EINVAL | libc::ENODEV | libc::EOPNOTSUPP | libc::ENOSYS
    )
}

fn is_environment_refusal_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EACCES | libc::ENODEV | libc::ENOENT | libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM
    )
}

fn check_nonempty(field: &str, value: &str, failures: &mut Vec<String>) {
    if value.trim().is_empty() {
        failures.push(format!("{field} must not be empty"));
    }
}

fn check_runtime_provenance(field: &str, value: &str, failures: &mut Vec<String>) {
    check_nonempty(field, value, failures);
    if matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "unknown" | "none" | "n/a"
    ) {
        failures.push(format!("{field} must identify the exercised runtime"));
    }
}

fn check_equal(field: &str, actual: &str, expected: &str, failures: &mut Vec<String>) {
    if actual != expected {
        failures.push(format!("{field} must be `{expected}`, found `{actual}`"));
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;
    use crate::evidence_artifact_manifest::{
        BlockingIssueRef, EvidenceArtifactManifest, EVIDENCE_ARTIFACT_MANIFEST_VERSION,
    };

    fn receipt(operation: &str) -> Value {
        json!({
            "operation": operation,
            "requested_ack_floor": "local-intent",
            "earned_ack_class": "local-intent",
            "disposition": "durable-posix",
            "convergence": "satisfied",
            "durability_state": "DurableIntent",
            "target_inode": 7,
            "target_offset": 0,
            "target_length": 0,
            "target_has_range": false,
            "evidence_ref_count": LOCAL_INTENT_EVIDENCE_REF_COUNT,
            "refusal_reason": "None",
            "posix_durable_success": true,
            "satisfies_requested_ack_floor": true
        })
    }

    fn current_nonpass_report() -> Value {
        let rows = EXPECTED_ROWS
            .iter()
            .map(|expected| {
                if matches!(expected.row_id, "sync-write-receipt" | "odsync-receipt") {
                    let observed = if expected.row_id == "sync-write-receipt" {
                        "fsync"
                    } else {
                        "fdatasync"
                    };
                    json!({
                        "row_id": expected.row_id,
                        "syscall": expected.syscall,
                        "expected_receipt_operation": expected.receipt_operation,
                        "syscall_result": "success",
                        "errno": null,
                        "observed_receipts": [receipt(observed)],
                        "outcome": "product-fail",
                        "reason": "mounted syscall returned success without its exact receipt"
                    })
                } else if expected.refusal_allowed {
                    json!({
                        "row_id": expected.row_id,
                        "syscall": expected.syscall,
                        "expected_receipt_operation": expected.receipt_operation,
                        "syscall_result": "refused",
                        "errno": libc::EINVAL,
                        "observed_receipts": [],
                        "outcome": "pass",
                        "reason": "unsupported mounted operation failed closed"
                    })
                } else {
                    json!({
                        "row_id": expected.row_id,
                        "syscall": expected.syscall,
                        "expected_receipt_operation": expected.receipt_operation,
                        "syscall_result": "success",
                        "errno": null,
                        "observed_receipts": [receipt(expected.receipt_operation)],
                        "outcome": "pass",
                        "reason": "mounted syscall returned success with its exact receipt"
                    })
                }
            })
            .collect::<Vec<_>>();
        json!({
            "report_version": ACK_RUNTIME_REPORT_VERSION,
            "claim_id": ACK_RUNTIME_CLAIM_ID,
            "issue": ACK_RUNTIME_ISSUE_URL,
            "parent_issue": ACK_RUNTIME_PARENT_ISSUE_URL,
            "run_id": "29666546112/1",
            "source_ref": "16f39e777859e52beb858dd3e82c4f6383541d3d",
            "generated_at": "2026-07-19T00:35:47Z",
            "validation_tier": "mounted-userspace",
            "command": ACK_RUNTIME_COMMAND,
            "backend": {
                "kind": ACK_RUNTIME_LIVE_BACKEND_KIND,
                "carrier": "linux-7.0-qemu-guest",
                "kernel_release": "7.0.0",
                "mount_options": ["rw", "nodev", "nosuid", "subtype=tidefs"],
                "receipt_source": ACK_RUNTIME_RECEIPT_SOURCE,
                "fault_injection": "none"
            },
            "rows": rows,
            "summary": {
                "status": "product-fail",
                "passed": 5,
                "product_failed": 2,
                "harness_failed": 0,
                "environment_refused": 0,
                "skipped": 0
            },
            "residual_risk": [
                "bounded mounted runtime evidence",
                "product failure keeps the claim blocked"
            ]
        })
    }

    fn report_bytes(report: &Value) -> Vec<u8> {
        let mut bytes = serde_json::to_vec_pretty(report).expect("encode report fixture");
        bytes.push(b'\n');
        bytes
    }

    fn manifest_bytes(report_bytes: &[u8]) -> Vec<u8> {
        let report: RuntimeReport =
            serde_json::from_slice(report_bytes).expect("parse report fixture");
        let blocking_issues = if report.summary.status == ValidationStatus::Pass {
            Vec::new()
        } else {
            vec![BlockingIssueRef {
                repo: Some("tidefs/tidefs".to_string()),
                number: ACK_RUNTIME_BLOCKING_ISSUE,
                reason: Some(ACK_RUNTIME_BLOCKING_REASON.to_string()),
            }]
        };
        let manifest = EvidenceArtifactManifest {
            manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
            claim_id: ACK_RUNTIME_CLAIM_ID.to_string(),
            evidence_class: ACK_RUNTIME_EVIDENCE_CLASS.to_string(),
            validation_tier: report.validation_tier,
            scope: ack_runtime_manifest_scope(
                report.summary.status,
                report.summary.passed,
                report.summary.product_failed,
                report.summary.environment_refused,
            ),
            artifact_path: ACK_RUNTIME_ARTIFACT_PATH.to_string(),
            content_digest: content_digest_for_bytes(report_bytes),
            run_id: report.run_id,
            source_ref: report.source_ref,
            outcome: report.summary.status,
            residual_risk: report.residual_risk.join(" "),
            source: ACK_RUNTIME_SOURCE.to_string(),
            generated_at: report.generated_at,
            blocking_issues,
        };
        let mut bytes = manifest
            .to_json_pretty()
            .expect("encode manifest fixture")
            .into_bytes();
        bytes.push(b'\n');
        bytes
    }

    fn assert_failure_contains(error: AckRuntimeEvidenceError, needle: &str) {
        assert!(
            error
                .failures()
                .iter()
                .any(|failure| failure.contains(needle)),
            "expected failure containing {needle:?}, got {:?}",
            error.failures()
        );
    }

    #[test]
    fn current_five_pass_two_fail_report_is_valid_evidence() {
        let report = report_bytes(&current_nonpass_report());
        let manifest = manifest_bytes(&report);
        validate_ack_runtime_evidence_json(&report, &manifest)
            .expect("honest non-pass evidence must remain valid");
    }

    #[test]
    fn duplicate_and_missing_rows_are_rejected() {
        let mut report = current_nonpass_report();
        let rows = report["rows"].as_array_mut().expect("rows");
        rows.pop();
        rows.push(rows[0].clone());
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("row-set drift must fail");
        assert_failure_contains(error.clone(), "duplicate row_id");
        assert_failure_contains(error, "missing row_id `fsyncdir-receipt`");
    }

    #[test]
    fn successful_pass_requires_exact_operation_receipt() {
        let mut report = current_nonpass_report();
        report["rows"][0]["outcome"] = json!("pass");
        report["summary"]["passed"] = json!(6);
        report["summary"]["product_failed"] = json!(1);
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("false exact-operation pass must fail");
        assert_failure_contains(error, "requires an exact earned `sync-write` receipt");
    }

    #[test]
    fn forged_volatile_receipt_cannot_earn_a_pass() {
        let mut report = current_nonpass_report();
        let receipt = &mut report["rows"][1]["observed_receipts"][0];
        receipt["earned_ack_class"] = json!("volatile-local");
        receipt["disposition"] = json!("weaker-unsafe-volatile");
        receipt["durability_state"] = json!("Volatile");
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("volatile receipt must not be accepted through copied booleans");
        assert_failure_contains(
            error,
            "claims to satisfy the requested floor without a supported durable receipt shape",
        );
    }

    #[test]
    fn unbound_receipt_target_cannot_earn_a_pass() {
        let mut report = current_nonpass_report();
        report["rows"][1]["observed_receipts"][0]["target_inode"] = Value::Null;
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("unbound receipt target must fail closed");
        assert_failure_contains(error, "target does not match operation `fsync`");
    }

    #[test]
    fn summary_drift_is_rejected() {
        let mut report = current_nonpass_report();
        report["summary"]["passed"] = json!(4);
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("summary drift must fail");
        assert_failure_contains(error, "summary.passed is 4, recomputed row count is 5");
    }

    #[test]
    fn unsupported_refusal_pass_is_mmap_only() {
        let mut report = current_nonpass_report();
        report["rows"][0]["outcome"] = json!("pass");
        report["rows"][0]["syscall_result"] = json!("refused");
        report["rows"][0]["errno"] = json!(libc::EINVAL);
        report["rows"][0]["observed_receipts"] = json!([]);
        report["summary"]["passed"] = json!(6);
        report["summary"]["product_failed"] = json!(1);
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("non-mmap refusal pass must fail");
        assert_failure_contains(error, "cannot treat unsupported refusal as pass");
    }

    #[test]
    fn manifest_provenance_must_match_report() {
        let report = report_bytes(&current_nonpass_report());
        let manifest = manifest_bytes(&report);
        let mut manifest_value: Value =
            serde_json::from_slice(&manifest).expect("parse manifest fixture");
        manifest_value["run_id"] = json!("different-run/1");
        let mut changed =
            serde_json::to_vec_pretty(&manifest_value).expect("encode changed manifest");
        changed.push(b'\n');
        let error = validate_ack_runtime_evidence_json(&report, &changed)
            .expect_err("manifest/report mismatch must fail");
        assert_failure_contains(error, "manifest run_id");
    }

    #[test]
    fn complete_environment_refusal_is_valid_nonpass_evidence() {
        let mut report = current_nonpass_report();
        for row in report["rows"].as_array_mut().expect("rows") {
            row["syscall_result"] = json!("environment-refused");
            row["errno"] = json!(libc::EPERM);
            row["observed_receipts"] = json!([]);
            row["outcome"] = json!("environment-refusal");
            row["reason"] = json!("mounted row was not exercised: mount refused");
        }
        report["summary"] = json!({
            "status": "environment-refusal",
            "passed": 0,
            "product_failed": 0,
            "harness_failed": 0,
            "environment_refused": 7,
            "skipped": 0
        });
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("environment refusal must not retain a live backend kind");
        assert_failure_contains(
            error,
            "backend.kind must be `fuse-mount-environment-refused`",
        );
        report["backend"]["kind"] = json!(ACK_RUNTIME_REFUSED_BACKEND_KIND);
        let report = report_bytes(&report);
        let manifest = manifest_bytes(&report);
        validate_ack_runtime_evidence_json(&report, &manifest)
            .expect("complete environment refusal must remain valid evidence");
    }

    #[test]
    fn exercised_rows_require_the_live_backend_kind() {
        let mut report = current_nonpass_report();
        report["backend"]["kind"] = json!(ACK_RUNTIME_REFUSED_BACKEND_KIND);
        let error = validate_ack_runtime_report_json(&report_bytes(&report))
            .expect_err("exercised rows must not use an environment-refusal backend");
        assert_failure_contains(error, "backend.kind must be `live-fuse-local-object-store`");
    }
}
