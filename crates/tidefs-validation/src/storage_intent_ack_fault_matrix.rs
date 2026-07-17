// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! QEMU acknowledgment-receipt fault-matrix support.
//!
//! The runtime row uses three Linux 7.0 QEMU boots against one raw virtio-blk
//! image.  The host harness kills only the QEMU processes that it launched:
//! once after a pre-ack record is durable and once after an earned local-intent
//! receipt record is durable.  The final boot verifies those crash boundaries
//! and exercises stale-media, under-quorum, and hidden-downgrade refusal gates.
//! This is fault-row evidence, not mounted-runtime or distributed-runtime proof.

use crate::evidence_artifact_manifest::{
    content_digest_for_bytes, EvidenceArtifactManifest, EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tidefs_local_filesystem::ack_receipt::{
    LocalAckOperation, LocalAckReceipt, LocalAckReceiptDisposition, LocalAckReceiptTarget,
    LOCAL_ACK_POLICY_ID, LOCAL_ACK_POLICY_REVISION,
};
use tidefs_storage_intent_core::{
    ack_receipt_satisfies_requested_floor, DurabilityReceiptState, DurabilityState, ProximityClass,
    StorageIntentGuaranteeClass, StorageIntentReceiptId, StorageIntentRefusalReason,
    StorageMediaClass, StorageMediaRole,
};

pub const ACK_FAULT_CLAIM_ID: &str = "storage.intent.ack_receipt_honesty.v1";
pub const ACK_FAULT_EVIDENCE_CLASS: &str = "storage-intent-ack-fault-matrix";
pub const ACK_FAULT_SOURCE: &str = "qemu-smoke-storage-intent-ack-fault-matrix-v1";
pub const ACK_FAULT_ARTIFACT_PATH: &str =
    "validation/artifacts/storage-intent/ack-receipt-fault-matrix.json";
pub const KILL_BEFORE_ACK_MARKER: &str = "TIDEFS_ACK_FAULT_KILL_BEFORE_ACK_READY";
pub const CRASH_AFTER_ACK_MARKER: &str = "TIDEFS_ACK_FAULT_CRASH_AFTER_ACK_READY";
pub const REPORT_BEGIN_MARKER: &str = "TIDEFS_ACK_FAULT_MATRIX_REPORT_BEGIN";
pub const REPORT_END_MARKER: &str = "TIDEFS_ACK_FAULT_MATRIX_REPORT_END";

const REPORT_SCHEMA_VERSION: u32 = 1;
const FAULT_RECORD_MAGIC: &[u8; 8] = b"TFSACKF1";
const FAULT_RECORD_VERSION: u32 = 1;
const FAULT_RECORD_BYTES: usize = 512;
const FAULT_RECORD_DIGEST_OFFSET: usize = 480;
const KILL_BEFORE_ACK_OFFSET: u64 = 0;
const CRASH_AFTER_ACK_OFFSET: u64 = 4096;
const KILL_BEFORE_ACK_SEQUENCE: u64 = 1;
const CRASH_AFTER_ACK_SEQUENCE: u64 = 2;
const FAULT_TARGET_INODE: u64 = 2224;
const FAULT_PAYLOAD_DIGEST: u64 = 0x2224_a55a_d00d_f17e;

const REQUIRED_ROW_IDS: [&str; 5] = [
    "kill-before-ack",
    "crash-after-ack",
    "stale-media",
    "under-quorum",
    "hidden-durable-to-volatile-downgrade",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum FaultRecordState {
    Prepared = 1,
    Acknowledged = 2,
}

impl FaultRecordState {
    fn from_discriminant(raw: u8) -> Option<Self> {
        match raw {
            1 => Some(Self::Prepared),
            2 => Some(Self::Acknowledged),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FaultRecord {
    state: FaultRecordState,
    sequence: u64,
    ack_class: StorageIntentGuaranteeClass,
    receipt_id: StorageIntentReceiptId,
    payload_digest: u64,
}

impl FaultRecord {
    fn prepared() -> Self {
        Self {
            state: FaultRecordState::Prepared,
            sequence: KILL_BEFORE_ACK_SEQUENCE,
            ack_class: StorageIntentGuaranteeClass::VolatileLocal,
            receipt_id: StorageIntentReceiptId::ZERO,
            payload_digest: FAULT_PAYLOAD_DIGEST,
        }
    }

    fn acknowledged(receipt: LocalAckReceipt) -> Self {
        Self {
            state: FaultRecordState::Acknowledged,
            sequence: CRASH_AFTER_ACK_SEQUENCE,
            ack_class: receipt.receipt.ack_class,
            receipt_id: receipt.receipt.receipt_id,
            payload_digest: FAULT_PAYLOAD_DIGEST,
        }
    }

    fn is_accepted_ack(self) -> bool {
        self.state == FaultRecordState::Acknowledged
            && self.sequence == CRASH_AFTER_ACK_SEQUENCE
            && self.ack_class == StorageIntentGuaranteeClass::LocalIntent
            && self.receipt_id != StorageIntentReceiptId::ZERO
            && self.payload_digest == FAULT_PAYLOAD_DIGEST
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckFaultRunProvenance {
    pub source_ref: String,
    pub run_id: String,
    pub generated_at: String,
    pub kernel_release: String,
}

impl AckFaultRunProvenance {
    pub fn from_qemu_guest() -> Result<Self, String> {
        let cmdline = fs::read_to_string("/proc/cmdline")
            .map_err(|error| format!("read QEMU guest /proc/cmdline: {error}"))?;
        if !cmdline
            .split_ascii_whitespace()
            .any(|arg| arg == "tidefs.ack_fault_validation=1")
        {
            return Err(
                "environment refusal: acknowledgment fault row requires the QEMU guest marker"
                    .to_string(),
            );
        }

        let source_ref = kernel_argument(&cmdline, "tidefs.source_ref=")?;
        let run_id = kernel_argument(&cmdline, "tidefs.run_id=")?;
        let generated_at = kernel_argument(&cmdline, "tidefs.generated_at=")?;
        let kernel_release = fs::read_to_string("/proc/sys/kernel/osrelease")
            .map_err(|error| format!("read QEMU guest kernel release: {error}"))?
            .trim()
            .to_string();
        if !kernel_release.starts_with("7.") {
            return Err(format!(
                "environment refusal: acknowledgment fault row requires Linux 7.0, found `{kernel_release}`"
            ));
        }

        let provenance = Self {
            source_ref,
            run_id,
            generated_at,
            kernel_release,
        };
        provenance.validate()?;
        Ok(provenance)
    }

    fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            ("source_ref", self.source_ref.as_str()),
            ("run_id", self.run_id.as_str()),
            ("generated_at", self.generated_at.as_str()),
            ("kernel_release", self.kernel_release.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(format!("{field} must not be empty"));
            }
        }
        if !self.generated_at.contains('T') || !self.generated_at.ends_with('Z') {
            return Err(format!(
                "generated_at must be an RFC3339-style UTC timestamp, found `{}`",
                self.generated_at
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckFaultQemuEnvironment {
    pub guest_detected: bool,
    pub kernel_release: String,
    pub boot_phases: Vec<String>,
    pub crash_injection: String,
    pub fault_media: String,
    pub fault_media_cache_mode: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckFaultRow {
    pub row_id: String,
    pub fault_class: String,
    pub injected_or_observed_condition: String,
    pub policy_revision: u64,
    pub expected_legal_outcomes: Vec<String>,
    pub forbidden_outcomes: Vec<String>,
    pub receipt_result_refs: Vec<String>,
    pub recovery_refs: Vec<String>,
    pub operator_visibility: String,
    pub artifact_retention: String,
    pub observed_outcome: String,
    pub status: ValidationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckFaultSummary {
    pub passed: usize,
    pub product_failed: usize,
    pub harness_failed: usize,
    pub environment_refused: usize,
    pub skipped: usize,
    pub status: ValidationStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckFaultMatrixReport {
    pub schema_version: u32,
    pub claim_id: String,
    pub evidence_class: String,
    pub validation_tier: ValidationTier,
    pub source: String,
    pub source_ref: String,
    pub run_id: String,
    pub generated_at: String,
    pub qemu: AckFaultQemuEnvironment,
    pub rows: Vec<AckFaultRow>,
    pub summary: AckFaultSummary,
    pub residual_risk: Vec<String>,
}

impl AckFaultMatrixReport {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        self.summary.status == ValidationStatus::Pass
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut failures = Vec::new();
        if self.schema_version != REPORT_SCHEMA_VERSION {
            failures.push(format!(
                "schema_version must be {REPORT_SCHEMA_VERSION}, found {}",
                self.schema_version
            ));
        }
        if self.claim_id != ACK_FAULT_CLAIM_ID {
            failures.push(format!("unexpected claim_id `{}`", self.claim_id));
        }
        if self.evidence_class != ACK_FAULT_EVIDENCE_CLASS {
            failures.push(format!(
                "unexpected evidence_class `{}`",
                self.evidence_class
            ));
        }
        if self.validation_tier != ValidationTier::QemuGuest {
            failures.push(format!(
                "validation_tier must be qemu-guest, found {}",
                self.validation_tier
            ));
        }
        if self.source != ACK_FAULT_SOURCE {
            failures.push(format!("unexpected source `{}`", self.source));
        }
        if !self.qemu.guest_detected {
            failures.push("qemu.guest_detected must be true".to_string());
        }
        if !self.qemu.kernel_release.starts_with("7.") {
            failures.push(format!(
                "qemu.kernel_release must identify Linux 7.0, found `{}`",
                self.qemu.kernel_release
            ));
        }
        if self.qemu.boot_phases
            != ["kill-before-ack", "crash-after-ack", "verify"]
                .map(str::to_string)
                .to_vec()
        {
            failures.push("qemu.boot_phases must record the three ordered boots".to_string());
        }
        if self.residual_risk.is_empty()
            || self.residual_risk.iter().any(|risk| risk.trim().is_empty())
        {
            failures.push("residual_risk must record concrete remaining boundaries".to_string());
        }
        if let Err(error) = (AckFaultRunProvenance {
            source_ref: self.source_ref.clone(),
            run_id: self.run_id.clone(),
            generated_at: self.generated_at.clone(),
            kernel_release: self.qemu.kernel_release.clone(),
        })
        .validate()
        {
            failures.push(error);
        }

        let row_ids: BTreeSet<&str> = self.rows.iter().map(|row| row.row_id.as_str()).collect();
        let required_ids: BTreeSet<&str> = REQUIRED_ROW_IDS.into_iter().collect();
        if self.rows.len() != REQUIRED_ROW_IDS.len() || row_ids != required_ids {
            failures.push(format!(
                "rows must contain exactly {:?}, found {:?}",
                REQUIRED_ROW_IDS, row_ids
            ));
        }
        for row in &self.rows {
            if row.policy_revision != LOCAL_ACK_POLICY_REVISION.0 {
                failures.push(format!(
                    "row `{}` policy_revision must be {}, found {}",
                    row.row_id, LOCAL_ACK_POLICY_REVISION.0, row.policy_revision
                ));
            }
            if row.fault_class.trim().is_empty()
                || row.injected_or_observed_condition.trim().is_empty()
                || row.expected_legal_outcomes.is_empty()
                || row.forbidden_outcomes.is_empty()
                || row.receipt_result_refs.is_empty()
                || row.recovery_refs.is_empty()
                || row.operator_visibility.trim().is_empty()
                || row.artifact_retention.trim().is_empty()
                || row.observed_outcome.trim().is_empty()
            {
                failures.push(format!("row `{}` is missing required evidence", row.row_id));
            }
        }

        let expected_summary = summarize_rows(&self.rows);
        if self.summary != expected_summary {
            failures.push(format!(
                "summary does not match rows: expected {:?}, found {:?}",
                expected_summary, self.summary
            ));
        }

        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        }
    }
}

pub fn ensure_qemu_guest() -> Result<(), String> {
    let cmdline = fs::read_to_string("/proc/cmdline")
        .map_err(|error| format!("read QEMU guest /proc/cmdline: {error}"))?;
    if cmdline
        .split_ascii_whitespace()
        .any(|arg| arg == "tidefs.ack_fault_validation=1")
    {
        Ok(())
    } else {
        Err(
            "environment refusal: acknowledgment fault phase requires the QEMU guest marker"
                .to_string(),
        )
    }
}

pub fn prepare_kill_before_ack(media_path: impl AsRef<Path>) -> Result<(), String> {
    write_fault_record(
        media_path.as_ref(),
        KILL_BEFORE_ACK_OFFSET,
        FaultRecord::prepared(),
    )
}

pub fn prepare_crash_after_ack(media_path: impl AsRef<Path>) -> Result<(), String> {
    let receipt = durable_fault_receipt(CRASH_AFTER_ACK_SEQUENCE, LocalAckOperation::Fsync);
    if !receipt.satisfies_requested_ack_floor() {
        return Err(
            "source receipt did not earn the local-intent floor before crash injection".to_string(),
        );
    }
    write_fault_record(
        media_path.as_ref(),
        CRASH_AFTER_ACK_OFFSET,
        FaultRecord::acknowledged(receipt),
    )
}

pub fn verify_fault_matrix(
    media_path: impl AsRef<Path>,
    provenance: AckFaultRunProvenance,
) -> Result<AckFaultMatrixReport, String> {
    provenance.validate()?;
    let media_path = media_path.as_ref();
    let mut rows = Vec::with_capacity(REQUIRED_ROW_IDS.len());

    let kill_row = match read_fault_record(media_path, KILL_BEFORE_ACK_OFFSET) {
        Ok(record) => {
            let passed = record.state == FaultRecordState::Prepared
                && record.sequence == KILL_BEFORE_ACK_SEQUENCE
                && record.receipt_id == StorageIntentReceiptId::ZERO
                && !record.is_accepted_ack();
            row(
                "kill-before-ack",
                "guest-crash-before-ack-publication",
                "The first QEMU boot durably wrote only a pre-ack record; the host then sent SIGKILL to that owned QEMU process.",
                &["no-success-receipt", "typed-refusal-or-unknown"],
                &["durable-success-without-ack-publication"],
                &[format!("pre-ack-sequence:{}", record.sequence)],
                &["virtio-blk-slot:0".to_string()],
                "fail-closed:no-ack-receipt",
                if passed {
                    "Recovered the prepared record with a zero receipt id and did not accept it as an acknowledgment."
                } else {
                    "The recovered pre-ack record was incorrectly shaped as an accepted acknowledgment."
                },
                passed,
            )
        }
        Err(error) => row(
            "kill-before-ack",
            "guest-crash-before-ack-publication",
            "The first QEMU boot was killed after the pre-ack durability marker.",
            &["no-success-receipt", "typed-refusal-or-unknown"],
            &["durable-success-without-ack-publication"],
            &["pre-ack-record-unreadable".to_string()],
            &["virtio-blk-slot:0".to_string()],
            "fail-closed:recovery-error",
            &format!("Could not recover the pre-ack record: {error}"),
            false,
        ),
    };
    rows.push(kill_row);

    let crash_bytes = read_fault_record_bytes(media_path, CRASH_AFTER_ACK_OFFSET);
    let crash_row = match crash_bytes {
        Ok(bytes) => match decode_fault_record(&bytes) {
            Ok(record) => {
                let recovered =
                    durable_fault_receipt(CRASH_AFTER_ACK_SEQUENCE, LocalAckOperation::Fsync);
                let mut corrupted = bytes;
                corrupted[64] ^= 0x80;
                let corrupted_refused = decode_fault_record(&corrupted).is_err();
                let passed = record.is_accepted_ack()
                    && record.receipt_id == recovered.receipt.receipt_id
                    && recovered.satisfies_requested_ack_floor()
                    && corrupted_refused;
                row(
                    "crash-after-ack",
                    "guest-crash-after-durable-ack-publication",
                    "The second QEMU boot synced an earned local-intent record, published the ack marker, and was then killed by the host.",
                    &["recover-exact-earned-receipt", "refuse-corrupt-receipt"],
                    &["silent-downgrade", "accept-corrupt-receipt"],
                    &[format!(
                        "receipt-id:{}",
                        hex_bytes(&record.receipt_id.0)
                    )],
                    &["virtio-blk-slot:4096".to_string(), "record-blake3".to_string()],
                    "recovered:local-intent-or-refuse",
                    if passed {
                        "Recovered the exact earned local-intent receipt after the crash and rejected an in-memory corrupt copy."
                    } else {
                        "The post-ack record did not recover as the exact earned local-intent receipt."
                    },
                    passed,
                )
            }
            Err(error) => row(
                "crash-after-ack",
                "guest-crash-after-durable-ack-publication",
                "The second QEMU boot was killed after the durable ack marker.",
                &["recover-exact-earned-receipt", "refuse-corrupt-receipt"],
                &["silent-downgrade", "accept-corrupt-receipt"],
                &["post-ack-record-invalid".to_string()],
                &["virtio-blk-slot:4096".to_string()],
                "fail-closed:invalid-recovery-record",
                &format!("The post-ack record failed validation: {error}"),
                false,
            ),
        },
        Err(error) => row(
            "crash-after-ack",
            "guest-crash-after-durable-ack-publication",
            "The second QEMU boot was killed after the durable ack marker.",
            &["recover-exact-earned-receipt", "refuse-corrupt-receipt"],
            &["silent-downgrade", "accept-corrupt-receipt"],
            &["post-ack-record-unreadable".to_string()],
            &["virtio-blk-slot:4096".to_string()],
            "fail-closed:recovery-error",
            &format!("Could not read the post-ack record: {error}"),
            false,
        ),
    };
    rows.push(crash_row);

    let target = fault_target();
    let mut stale_receipt = durable_fault_receipt(3, LocalAckOperation::Fdatasync);
    stale_receipt.media_capability_ref.generation = stale_receipt
        .media_capability_ref
        .generation
        .saturating_sub(1);
    let stale_refusal = LocalAckReceipt::refused_unmet_floor(
        3,
        LocalAckOperation::Fdatasync,
        target,
        StorageIntentGuaranteeClass::LocalIntent,
        StorageIntentGuaranteeClass::VolatileLocal,
        StorageIntentRefusalReason::StaleMediaCapabilityEvidence,
    );
    let stale_passed = !stale_receipt.satisfies_requested_ack_floor()
        && stale_refusal.disposition == LocalAckReceiptDisposition::Refused
        && stale_refusal.refusal_reason()
            == StorageIntentRefusalReason::StaleMediaCapabilityEvidence;
    rows.push(row(
        "stale-media",
        "stale-media-capability-evidence",
        "The final QEMU boot changed the media-capability generation outside the receipt evidence cut.",
        &["typed-refusal", "unknown-evidence"],
        &["durable-success-from-stale-media"],
        &[
            format!(
                "stale-media-evidence:{}",
                hex_bytes(&stale_receipt.media_capability_ref.id.0)
            ),
            format!(
                "refusal-evidence:{}",
                hex_bytes(&stale_refusal.refusal.evidence.id.0)
            ),
        ],
        &["local-ack-exact-evidence-cut".to_string()],
        StorageIntentRefusalReason::StaleMediaCapabilityEvidence.as_str(),
        if stale_passed {
            "The stale evidence cut was rejected and projected as a typed stale-media refusal."
        } else {
            "The stale media evidence was accepted or did not project the required refusal."
        },
        stale_passed,
    ));

    let under_quorum = LocalAckReceipt::refused_unmet_floor(
        4,
        LocalAckOperation::SyncWrite,
        target,
        StorageIntentGuaranteeClass::QuorumIntent,
        StorageIntentGuaranteeClass::VolatileReplicated,
        StorageIntentRefusalReason::UnderQuorum,
    );
    let under_quorum_passed = under_quorum.disposition == LocalAckReceiptDisposition::Refused
        && under_quorum.refusal_reason() == StorageIntentRefusalReason::UnderQuorum
        && !under_quorum.is_posix_durable_success()
        && !under_quorum.satisfies_requested_ack_floor()
        && !ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::QuorumIntent,
            StorageIntentGuaranteeClass::VolatileReplicated,
        );
    rows.push(row(
        "under-quorum",
        "receipt-gate-under-quorum",
        "The final QEMU boot evaluated a quorum-intent request with only volatile-replicated evidence.",
        &["typed-refusal"],
        &["quorum-success-from-under-quorum-evidence"],
        &[
            format!(
                "attempted-receipt:{}",
                hex_bytes(&under_quorum.receipt.receipt_id.0)
            ),
            format!(
                "refusal-evidence:{}",
                hex_bytes(&under_quorum.refusal.evidence.id.0)
            ),
        ],
        &["guarantee-capability-predicate".to_string()],
        StorageIntentRefusalReason::UnderQuorum.as_str(),
        if under_quorum_passed {
            "The quorum-intent request was refused; volatile replicated evidence was not upgraded into quorum durability."
        } else {
            "The under-quorum evidence satisfied or escaped the typed refusal gate."
        },
        under_quorum_passed,
    ));

    let mut downgraded = durable_fault_receipt(5, LocalAckOperation::FsyncDirectory);
    downgraded.receipt.ack_class = StorageIntentGuaranteeClass::VolatileLocal;
    downgraded.receipt.durability = DurabilityReceiptState {
        state: DurabilityState::Volatile,
        observed_lag_ms: u64::MAX,
        lag_known: false,
    };
    downgraded.receipt.proximity = ProximityClass::LocalRam;
    downgraded.receipt.media_role = StorageMediaRole::RamVolatileAuthority;
    downgraded.receipt.media_class = StorageMediaClass::SystemRam;
    let downgrade_refusal = LocalAckReceipt::refused_unmet_floor(
        5,
        LocalAckOperation::FsyncDirectory,
        target,
        StorageIntentGuaranteeClass::LocalIntent,
        StorageIntentGuaranteeClass::VolatileLocal,
        StorageIntentRefusalReason::ReceiptWouldWeaken,
    );
    let downgrade_passed = downgraded.disposition == LocalAckReceiptDisposition::DurablePosix
        && !downgraded.is_posix_durable_success()
        && !downgraded.satisfies_requested_ack_floor()
        && !ack_receipt_satisfies_requested_floor(
            StorageIntentGuaranteeClass::LocalIntent,
            StorageIntentGuaranteeClass::VolatileLocal,
        )
        && downgrade_refusal.disposition == LocalAckReceiptDisposition::Refused
        && downgrade_refusal.refusal_reason() == StorageIntentRefusalReason::ReceiptWouldWeaken;
    rows.push(row(
        "hidden-durable-to-volatile-downgrade",
        "attempted-hidden-ack-floor-weakening",
        "The final QEMU boot changed an otherwise success-shaped local-intent receipt to volatile RAM while leaving the outer success disposition intact.",
        &["typed-refusal", "unsafe-visible-only-with-explicit-policy"],
        &["durable-success-from-volatile-evidence"],
        &[
            format!(
                "downgraded-receipt:{}",
                hex_bytes(&downgraded.receipt.receipt_id.0)
            ),
            format!(
                "refusal-evidence:{}",
                hex_bytes(&downgrade_refusal.refusal.evidence.id.0)
            ),
        ],
        &["local-ack-shape-consistency".to_string(), "guarantee-capability-predicate".to_string()],
        StorageIntentRefusalReason::ReceiptWouldWeaken.as_str(),
        if downgrade_passed {
            "The inner receipt checks rejected the volatile downgrade despite the retained success disposition, and the explicit projection was a typed refusal."
        } else {
            "The volatile downgrade escaped the receipt floor or typed refusal checks."
        },
        downgrade_passed,
    ));

    let summary = summarize_rows(&rows);
    let report = AckFaultMatrixReport {
        schema_version: REPORT_SCHEMA_VERSION,
        claim_id: ACK_FAULT_CLAIM_ID.to_string(),
        evidence_class: ACK_FAULT_EVIDENCE_CLASS.to_string(),
        validation_tier: ValidationTier::QemuGuest,
        source: ACK_FAULT_SOURCE.to_string(),
        source_ref: provenance.source_ref,
        run_id: provenance.run_id,
        generated_at: provenance.generated_at,
        qemu: AckFaultQemuEnvironment {
            guest_detected: true,
            kernel_release: provenance.kernel_release,
            boot_phases: ["kill-before-ack", "crash-after-ack", "verify"]
                .map(str::to_string)
                .to_vec(),
            crash_injection: "host-sigkill-owned-qemu-process".to_string(),
            fault_media: "raw-virtio-blk".to_string(),
            fault_media_cache_mode: "cache-none".to_string(),
        },
        rows,
        summary,
        residual_risk: vec![
            "This QEMU row exercises raw virtio-blk persistence and receipt evaluation; it does not exercise mounted write, fsync, fdatasync, O_DSYNC, mmap, namespace, or fsyncdir runtime.".to_string(),
            "The under-quorum row injects the typed receipt-gate condition inside the guest; it is not multi-process distributed quorum execution.".to_string(),
            "The acknowledgment honesty claim remains blocked until mounted-runtime and claims-gate-review evidence also exists; this artifact does not strengthen successor, comparator, release, or product wording.".to_string(),
        ],
    };
    report.validate()?;
    Ok(report)
}

pub fn write_manifest_for_report(
    report_path: impl AsRef<Path>,
    artifact_root: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
) -> Result<EvidenceArtifactManifest, String> {
    let report_path = report_path.as_ref();
    let artifact_root = artifact_root.as_ref();
    let manifest_path = manifest_path.as_ref();
    let report_bytes = fs::read(report_path)
        .map_err(|error| format!("read acknowledgment fault report: {error}"))?;
    let report: AckFaultMatrixReport = serde_json::from_slice(&report_bytes)
        .map_err(|error| format!("parse acknowledgment fault report JSON: {error}"))?;
    report.validate()?;

    let manifest = EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: ACK_FAULT_CLAIM_ID.to_string(),
        evidence_class: ACK_FAULT_EVIDENCE_CLASS.to_string(),
        validation_tier: ValidationTier::QemuGuest,
        scope: format!(
            "Linux 7.0 QEMU three-boot raw-media acknowledgment fault matrix covering kill-before-ack, crash-after-ack, stale media, under-quorum refusal, and hidden durable-to-volatile downgrade detection; fault-only scope, not mounted or distributed runtime; run={} ref={} kernel={}",
            report.run_id, report.source_ref, report.qemu.kernel_release
        ),
        artifact_path: ACK_FAULT_ARTIFACT_PATH.to_string(),
        content_digest: content_digest_for_bytes(&report_bytes),
        run_id: report.run_id.clone(),
        source_ref: report.source_ref.clone(),
        outcome: report.summary.status,
        residual_risk: report.residual_risk.join(" "),
        source: ACK_FAULT_SOURCE.to_string(),
        generated_at: report.generated_at.clone(),
        blocking_issues: Vec::new(),
    };
    let mut manifest_json = manifest
        .to_json_pretty()
        .map_err(|error| error.to_string())?;
    manifest_json.push('\n');
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("create manifest directory: {error}"))?;
    }
    fs::write(manifest_path, manifest_json)
        .map_err(|error| format!("write acknowledgment fault manifest: {error}"))?;
    manifest
        .verify_artifact_digest(artifact_root)
        .map_err(|error| error.to_string())?;
    Ok(manifest)
}

fn kernel_argument(cmdline: &str, prefix: &str) -> Result<String, String> {
    cmdline
        .split_ascii_whitespace()
        .find_map(|argument| argument.strip_prefix(prefix))
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .ok_or_else(|| format!("QEMU guest cmdline is missing `{prefix}<value>`"))
}

fn fault_target() -> LocalAckReceiptTarget {
    LocalAckReceiptTarget::range(FAULT_TARGET_INODE, 0, 4096)
}

fn durable_fault_receipt(sequence: u64, operation: LocalAckOperation) -> LocalAckReceipt {
    LocalAckReceipt::durable_intent(
        sequence,
        operation,
        fault_target(),
        Some(FAULT_PAYLOAD_DIGEST),
    )
}

fn row(
    row_id: &str,
    fault_class: &str,
    condition: &str,
    expected_legal_outcomes: &[&str],
    forbidden_outcomes: &[&str],
    receipt_result_refs: &[String],
    recovery_refs: &[String],
    operator_visibility: &str,
    observed_outcome: &str,
    passed: bool,
) -> AckFaultRow {
    AckFaultRow {
        row_id: row_id.to_string(),
        fault_class: fault_class.to_string(),
        injected_or_observed_condition: condition.to_string(),
        policy_revision: LOCAL_ACK_POLICY_REVISION.0,
        expected_legal_outcomes: expected_legal_outcomes
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        forbidden_outcomes: forbidden_outcomes
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        receipt_result_refs: receipt_result_refs.to_vec(),
        recovery_refs: recovery_refs.to_vec(),
        operator_visibility: operator_visibility.to_string(),
        artifact_retention: "exact-source-controlled-promotion-candidate".to_string(),
        observed_outcome: observed_outcome.to_string(),
        status: if passed {
            ValidationStatus::Pass
        } else {
            ValidationStatus::ProductFail
        },
    }
}

fn summarize_rows(rows: &[AckFaultRow]) -> AckFaultSummary {
    let count = |status| rows.iter().filter(|row| row.status == status).count();
    let passed = count(ValidationStatus::Pass);
    let product_failed = count(ValidationStatus::ProductFail);
    let harness_failed = count(ValidationStatus::HarnessFail);
    let environment_refused = count(ValidationStatus::EnvironmentRefusal);
    let skipped = count(ValidationStatus::Skip);
    let status = if product_failed > 0 {
        ValidationStatus::ProductFail
    } else if harness_failed > 0 {
        ValidationStatus::HarnessFail
    } else if environment_refused > 0 {
        ValidationStatus::EnvironmentRefusal
    } else if skipped > 0 {
        ValidationStatus::Skip
    } else {
        ValidationStatus::Pass
    };
    AckFaultSummary {
        passed,
        product_failed,
        harness_failed,
        environment_refused,
        skipped,
        status,
    }
}

fn write_fault_record(path: &Path, offset: u64, record: FaultRecord) -> Result<(), String> {
    let bytes = encode_fault_record(record);
    let mut media = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|error| format!("open fault media `{}`: {error}", path.display()))?;
    media
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek fault media to {offset}: {error}"))?;
    media
        .write_all(&bytes)
        .map_err(|error| format!("write fault record at {offset}: {error}"))?;
    media
        .sync_all()
        .map_err(|error| format!("sync fault record at {offset}: {error}"))?;
    Ok(())
}

fn read_fault_record(path: &Path, offset: u64) -> Result<FaultRecord, String> {
    decode_fault_record(&read_fault_record_bytes(path, offset)?)
}

fn read_fault_record_bytes(path: &Path, offset: u64) -> Result<[u8; FAULT_RECORD_BYTES], String> {
    let mut media = OpenOptions::new()
        .read(true)
        .open(path)
        .map_err(|error| format!("open fault media `{}`: {error}", path.display()))?;
    media
        .seek(SeekFrom::Start(offset))
        .map_err(|error| format!("seek fault media to {offset}: {error}"))?;
    let mut bytes = [0_u8; FAULT_RECORD_BYTES];
    media
        .read_exact(&mut bytes)
        .map_err(|error| format!("read fault record at {offset}: {error}"))?;
    Ok(bytes)
}

fn encode_fault_record(record: FaultRecord) -> [u8; FAULT_RECORD_BYTES] {
    let mut bytes = [0_u8; FAULT_RECORD_BYTES];
    bytes[..8].copy_from_slice(FAULT_RECORD_MAGIC);
    bytes[8..12].copy_from_slice(&FAULT_RECORD_VERSION.to_le_bytes());
    bytes[12] = record.state as u8;
    bytes[13] = record.ack_class.to_discriminant();
    bytes[16..24].copy_from_slice(&record.sequence.to_le_bytes());
    bytes[24..40].copy_from_slice(&LOCAL_ACK_POLICY_ID.0);
    bytes[40..48].copy_from_slice(&LOCAL_ACK_POLICY_REVISION.0.to_le_bytes());
    bytes[48..64].copy_from_slice(&record.receipt_id.0);
    bytes[64..72].copy_from_slice(&record.payload_digest.to_le_bytes());
    let digest = blake3::hash(&bytes[..FAULT_RECORD_DIGEST_OFFSET]);
    bytes[FAULT_RECORD_DIGEST_OFFSET..].copy_from_slice(digest.as_bytes());
    bytes
}

fn decode_fault_record(bytes: &[u8; FAULT_RECORD_BYTES]) -> Result<FaultRecord, String> {
    if &bytes[..8] != FAULT_RECORD_MAGIC {
        return Err("fault record magic mismatch".to_string());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("fixed version slice"));
    if version != FAULT_RECORD_VERSION {
        return Err(format!(
            "fault record version must be {FAULT_RECORD_VERSION}, found {version}"
        ));
    }
    let expected_digest = blake3::hash(&bytes[..FAULT_RECORD_DIGEST_OFFSET]);
    if &bytes[FAULT_RECORD_DIGEST_OFFSET..] != expected_digest.as_bytes() {
        return Err("fault record digest mismatch".to_string());
    }
    let state = FaultRecordState::from_discriminant(bytes[12])
        .ok_or_else(|| format!("unknown fault record state {}", bytes[12]))?;
    let ack_class = StorageIntentGuaranteeClass::from_discriminant(bytes[13])
        .ok_or_else(|| format!("unknown ack class {}", bytes[13]))?;
    let sequence = u64::from_le_bytes(bytes[16..24].try_into().expect("fixed sequence slice"));
    if bytes[24..40] != LOCAL_ACK_POLICY_ID.0 {
        return Err("fault record policy id mismatch".to_string());
    }
    let policy_revision =
        u64::from_le_bytes(bytes[40..48].try_into().expect("fixed revision slice"));
    if policy_revision != LOCAL_ACK_POLICY_REVISION.0 {
        return Err(format!(
            "fault record policy revision must be {}, found {policy_revision}",
            LOCAL_ACK_POLICY_REVISION.0
        ));
    }
    let mut receipt_id = [0_u8; 16];
    receipt_id.copy_from_slice(&bytes[48..64]);
    let payload_digest = u64::from_le_bytes(bytes[64..72].try_into().expect("fixed payload slice"));
    let record = FaultRecord {
        state,
        sequence,
        ack_class,
        receipt_id: StorageIntentReceiptId(receipt_id),
        payload_digest,
    };
    match record.state {
        FaultRecordState::Prepared
            if record.receipt_id != StorageIntentReceiptId::ZERO
                || record.ack_class != StorageIntentGuaranteeClass::VolatileLocal =>
        {
            Err("pre-ack record carried an acknowledgment".to_string())
        }
        FaultRecordState::Acknowledged if !record.is_accepted_ack() => {
            Err("acknowledged record did not carry an earned local-intent receipt".to_string())
        }
        _ => Ok(record),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance() -> AckFaultRunProvenance {
        AckFaultRunProvenance {
            source_ref: "0123456789abcdef0123456789abcdef01234567".to_string(),
            run_id: "qemu-test/1".to_string(),
            generated_at: "2026-07-17T08:29:21Z".to_string(),
            kernel_release: "7.0.0-tidefs-test".to_string(),
        }
    }

    fn prepared_media(path: &Path) {
        let media = fs::File::create(path).expect("create media");
        media.set_len(8192).expect("size media");
        drop(media);
        prepare_kill_before_ack(path).expect("prepare pre-ack record");
        prepare_crash_after_ack(path).expect("prepare post-ack record");
    }

    #[test]
    fn raw_fault_record_rejects_digest_corruption() {
        let mut bytes = encode_fault_record(FaultRecord::prepared());
        assert_eq!(
            decode_fault_record(&bytes).expect("decode prepared record"),
            FaultRecord::prepared()
        );
        bytes[64] ^= 1;
        assert_eq!(
            decode_fault_record(&bytes).expect_err("reject corrupt record"),
            "fault record digest mismatch"
        );
    }

    #[test]
    fn five_row_matrix_fails_closed() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let media_path = tempdir.path().join("fault-media.img");
        prepared_media(&media_path);
        let report = verify_fault_matrix(&media_path, provenance()).expect("verify matrix");
        assert!(report.is_pass());
        assert_eq!(report.rows.len(), 5);
        assert_eq!(report.summary.passed, 5);
        assert_eq!(report.summary.product_failed, 0);
        report.validate().expect("validate report schema");
    }

    #[test]
    fn manifest_binds_promotable_report_digest() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let media_path = tempdir.path().join("fault-media.img");
        prepared_media(&media_path);
        let report = verify_fault_matrix(&media_path, provenance()).expect("verify matrix");
        let report_path = tempdir.path().join(ACK_FAULT_ARTIFACT_PATH);
        fs::create_dir_all(report_path.parent().expect("report parent"))
            .expect("create report parent");
        let mut report_json = serde_json::to_string_pretty(&report).expect("serialize report");
        report_json.push('\n');
        fs::write(&report_path, report_json).expect("write report");
        let manifest_path = tempdir.path().join("evidence-manifest.json");
        let manifest = write_manifest_for_report(&report_path, tempdir.path(), &manifest_path)
            .expect("write manifest");
        assert_eq!(manifest.outcome, ValidationStatus::Pass);
        assert_eq!(manifest.validation_tier, ValidationTier::QemuGuest);
        assert_eq!(manifest.artifact_path, ACK_FAULT_ARTIFACT_PATH);
        manifest
            .verify_artifact_digest(tempdir.path())
            .expect("verify artifact digest");
    }
}
