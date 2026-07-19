// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! QEMU-guest helper-transform evidence for storage-intent data-shape honesty.
//!
//! The rows in this module execute current compression, checksum, encryption,
//! and erasure-coding helpers. They deliberately do not claim mounted transform
//! authority, compiled-policy receipt satisfaction, key-epoch lifecycle proof,
//! archive recall, dedupe-domain execution, coalescing, rebake, or source
//! retirement.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;
use serde_json::{json, Value};
use tidefs_checksum_tree::{DomainTag, ObjectDigest};
use tidefs_compression::{decode, encode, CompressionAlgorithm, CompressionError};
use tidefs_encryption::{decrypt_extent, encrypt_extent, DatasetDEK, EncryptionError, ExtentNonce};
use tidefs_erasure_coding::{
    encode_receipt_stripe, reconstruct_receipt_stripe, ErasureShard, ReceiptStripeError, ShardKind,
    StripeConfig,
};

use crate::evidence_artifact_manifest::{
    content_digest_for_bytes, BlockingIssueRef, EvidenceArtifactManifest,
    EVIDENCE_ARTIFACT_MANIFEST_VERSION,
};
use crate::validation_schema::ValidationTier;
use crate::validation_status::ValidationStatus;

pub const CLAIM_ID: &str = "storage.intent.data_shape_honesty.v1";
pub const ISSUE_URL: &str = "https://github.com/tidefs/tidefs/issues/1981";
pub const TRANSFORM_ARTIFACT_PATH: &str =
    "validation/artifacts/storage-intent/data-shape-transform-execution.json";
pub const TRANSFORM_MANIFEST_PATH: &str =
    "validation/artifacts/storage-intent/data-shape-transform-execution.manifest.json";
pub const PERFORMANCE_ARTIFACT_PATH: &str =
    "validation/artifacts/storage-intent/data-shape-performance-fault-rows.json";
pub const PERFORMANCE_MANIFEST_PATH: &str =
    "validation/artifacts/storage-intent/data-shape-performance-fault-rows.manifest.json";

const SOURCE: &str = "qemu-fuse-vm-data-shape-helper-runtime-v1";
const COMMAND: &str = "storage-intent-data-shape-runtime-validation";

const TRANSFORM_RESIDUAL_RISK: &[&str] = &[
    "The passing rows execute helper/library code in one QEMU guest; they do not prove mounted transform dispatch, raw-store conformance, compiled-policy receipt satisfaction, recovery, or source retirement.",
    "Dedupe-domain execution, key-epoch lifecycle proof, archive recall, coalescing, and rebake remain unexecuted, so the transform-execution evidence class and claim remain blocked.",
    "The rows do not widen compression, checksum, encryption, EC/archive, capacity, performance, production, release-readiness, or successor/comparator wording.",
];

const PERFORMANCE_RESIDUAL_RISK: &[&str] = &[
    "Elapsed guest timings are diagnostic observations without a stable CPU, workload, topology, or comparator baseline and are not a performance claim.",
    "Read amplification, key epochs, illegal dedupe domains, archive recall, coalescing, and rebake remain unexecuted; malformed-frame coverage is limited to compression frames and local EC shard sets.",
    "Local EC helper reconstruction and under-width refusal do not prove pool placement, distributed recovery, archive serving, degraded-read product safety, or availability.",
];

#[derive(Clone, Debug)]
pub struct DataShapeRunProvenance {
    pub run_id: String,
    pub source_ref: String,
    pub generated_at: String,
    pub carrier: String,
    pub kernel_release: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct DataShapeRuntimeReport {
    report_version: u32,
    claim_id: &'static str,
    issue: &'static str,
    run_id: String,
    source_ref: String,
    generated_at: String,
    validation_tier: ValidationTier,
    command: &'static str,
    artifact_scope: &'static str,
    outcome: ValidationStatus,
    runtime_execution_produced: bool,
    runtime_source: RuntimeSource,
    rows: Vec<DataShapeRuntimeRow>,
    summary: RuntimeSummary,
    non_claims: Vec<&'static str>,
    claim_effect: &'static str,
    residual_risk: Vec<&'static str>,
}

impl DataShapeRuntimeReport {
    #[must_use]
    pub fn outcome(&self) -> ValidationStatus {
        self.outcome
    }

    #[must_use]
    pub fn passed_rows(&self) -> usize {
        self.summary.passed
    }

    #[must_use]
    pub fn skipped_rows(&self) -> usize {
        self.summary.skipped
    }
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeSource {
    carrier: String,
    kernel_release: String,
    command: &'static str,
    code_paths: Vec<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
struct DataShapeRuntimeRow {
    row: &'static str,
    families: Vec<&'static str>,
    status: ValidationStatus,
    operation: &'static str,
    observation: Value,
    exact_boundary: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct RuntimeSummary {
    status: ValidationStatus,
    passed: usize,
    product_failed: usize,
    skipped: usize,
}

#[derive(Debug)]
pub struct DataShapeRuntimeReports {
    pub transform_execution: DataShapeRuntimeReport,
    pub performance_fault: DataShapeRuntimeReport,
}

#[derive(Debug)]
pub struct WrittenDataShapeEvidence {
    pub transform_artifact: PathBuf,
    pub transform_manifest: PathBuf,
    pub performance_artifact: PathBuf,
    pub performance_manifest: PathBuf,
}

fn payload() -> Vec<u8> {
    let pattern = b"tidefs-data-shape-runtime-evidence/";
    (0..64 * 1024)
        .map(|index| pattern[index % pattern.len()])
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

fn elapsed_nanos(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

fn executed_row(
    row: &'static str,
    families: Vec<&'static str>,
    operation: &'static str,
    exact_boundary: &'static str,
    run: impl FnOnce() -> Result<Value, String>,
) -> DataShapeRuntimeRow {
    match run() {
        Ok(observation) => DataShapeRuntimeRow {
            row,
            families,
            status: ValidationStatus::Pass,
            operation,
            observation,
            exact_boundary,
        },
        Err(reason) => DataShapeRuntimeRow {
            row,
            families,
            status: ValidationStatus::ProductFail,
            operation,
            observation: json!({ "failure": reason }),
            exact_boundary,
        },
    }
}

fn skipped_row(
    row: &'static str,
    families: Vec<&'static str>,
    operation: &'static str,
    missing_evidence: &'static str,
    exact_boundary: &'static str,
) -> DataShapeRuntimeRow {
    DataShapeRuntimeRow {
        row,
        families,
        status: ValidationStatus::Skip,
        operation,
        observation: json!({ "missing_evidence": missing_evidence }),
        exact_boundary,
    }
}

fn compression_roundtrip(algorithm: CompressionAlgorithm) -> Result<Value, String> {
    let source = payload();
    let started = Instant::now();
    let frame = encode::compress(algorithm, &source)
        .map_err(|error| format!("encode {algorithm:?} frame: {error}"))?;
    let decoded = decode::decompress(&frame)
        .map_err(|error| format!("decode {algorithm:?} frame: {error}"))?;
    let elapsed_ns = elapsed_nanos(started);
    if decoded != source {
        return Err(format!("{algorithm:?} decoded bytes differ from source"));
    }
    let observed_algorithm = decode::read_header(&frame)
        .map(|(observed, _)| format!("{observed:?}").to_lowercase())
        .ok_or_else(|| format!("{algorithm:?} frame header is not readable"))?;
    Ok(json!({
        "requested_algorithm": format!("{algorithm:?}").to_lowercase(),
        "observed_algorithm": observed_algorithm,
        "source_len": source.len(),
        "stored_frame_len": frame.len(),
        "source_digest": digest(&source),
        "stored_frame_digest": digest(&frame),
        "decoded_digest": digest(&decoded),
        "round_trip_exact": true,
        "guest_elapsed_ns": elapsed_ns,
    }))
}

fn stored_frame_digest_refusal() -> Result<Value, String> {
    let source = payload();
    let frame = encode::compress(CompressionAlgorithm::Zstd, &source)
        .map_err(|error| format!("encode stored frame: {error}"))?;
    let domain_key = DomainTag::ObjectContent.derive_key();
    let stored_digest = ObjectDigest::compute(&frame, &domain_key);
    if !stored_digest.verify(&frame, &domain_key) {
        return Err("stored-frame digest rejected original frame".to_string());
    }
    let mut tampered = frame.clone();
    let last = tampered
        .last_mut()
        .ok_or_else(|| "stored frame unexpectedly empty".to_string())?;
    *last ^= 0x80;
    if stored_digest.verify(&tampered, &domain_key) {
        return Err("stored-frame digest accepted tampered frame".to_string());
    }
    Ok(json!({
        "domain": DomainTag::ObjectContent.label(),
        "stored_frame_digest": stored_digest.to_string(),
        "original_verified": true,
        "tampered_refused": true,
        "tampered_frame_digest": digest(&tampered),
    }))
}

fn malformed_compression_refusal() -> Result<Value, String> {
    let source = payload();
    let frame = encode::compress(CompressionAlgorithm::Zstd, &source)
        .map_err(|error| format!("encode refusal fixture: {error}"))?;
    let mut unknown_algorithm = frame;
    unknown_algorithm[0] = 0xff;
    let unknown_refused = matches!(
        decode::decompress(&unknown_algorithm),
        Err(CompressionError::UnknownAlgorithm { byte: 0xff })
    );
    let short_refused = matches!(
        decode::decompress(&unknown_algorithm[..3]),
        Err(CompressionError::FrameTooShort { len: 3 })
    );
    if !unknown_refused || !short_refused {
        return Err(format!(
            "typed compression refusals missing: unknown={unknown_refused} short={short_refused}"
        ));
    }
    Ok(json!({
        "unknown_algorithm_refusal": "unknown-algorithm-0xff",
        "short_frame_refusal": "frame-too-short-len-3",
        "generic_success_forbidden": true,
    }))
}

fn encryption_roundtrip_and_refusal() -> Result<Value, String> {
    let source = payload();
    let key = DatasetDEK::from_bytes(&[0x11; 32]);
    let wrong_key = DatasetDEK::from_bytes(&[0x22; 32]);
    let nonce = ExtentNonce::derive(1981, 1, &key);
    let started = Instant::now();
    let encrypted = encrypt_extent(&source, &key, &nonce)
        .map_err(|error| format!("encrypt extent: {error}"))?;
    let decoded =
        decrypt_extent(&encrypted, &key).map_err(|error| format!("decrypt extent: {error}"))?;
    let elapsed_ns = elapsed_nanos(started);
    if decoded != source {
        return Err("AEAD decoded bytes differ from source".to_string());
    }
    let wrong_key_refused = matches!(
        decrypt_extent(&encrypted, &wrong_key),
        Err(EncryptionError::DecryptionFailed)
    );
    let mut tampered = encrypted.clone();
    let last = tampered
        .ciphertext
        .last_mut()
        .ok_or_else(|| "encrypted extent unexpectedly empty".to_string())?;
    *last ^= 0x01;
    let tamper_refused = matches!(
        decrypt_extent(&tampered, &key),
        Err(EncryptionError::DecryptionFailed)
    );
    if !wrong_key_refused || !tamper_refused {
        return Err(format!(
            "AEAD refusal missing: wrong_key={wrong_key_refused} tamper={tamper_refused}"
        ));
    }
    let mut stored_frame = encrypted.nonce.as_bytes().to_vec();
    stored_frame.extend_from_slice(&encrypted.ciphertext);
    Ok(json!({
        "algorithm": "chacha20-poly1305-helper",
        "source_len": source.len(),
        "stored_frame_len": stored_frame.len(),
        "source_digest": digest(&source),
        "stored_frame_digest": digest(&stored_frame),
        "decoded_digest": digest(&decoded),
        "round_trip_exact": true,
        "wrong_key_refused": true,
        "tampered_ciphertext_refused": true,
        "key_material_serialized": false,
        "guest_elapsed_ns": elapsed_ns,
    }))
}

fn ec_reconstruction_and_under_width_refusal() -> Result<Value, String> {
    let source = payload()[..96].to_vec();
    let config = StripeConfig {
        data_shards: 2,
        parity_shards: 1,
        shard_len: 64,
    };
    let started = Instant::now();
    let encoded = encode_receipt_stripe(&config, &source)
        .map_err(|error| format!("encode receipt stripe: {error:?}"))?;
    let mut degraded: Vec<_> = encoded.shards.iter().cloned().map(Some).collect();
    degraded[0] = None;
    let reconstructed = reconstruct_receipt_stripe(&config, &degraded)
        .map_err(|error| format!("reconstruct degraded receipt stripe: {error:?}"))?;
    let elapsed_ns = elapsed_nanos(started);
    if reconstructed.payload[..source.len()] != source {
        return Err("degraded EC reconstruction differs from source".to_string());
    }
    let rebuilt_indices: Vec<_> = reconstructed
        .rebuilt_shards
        .iter()
        .map(|shard| shard.index)
        .collect();
    if rebuilt_indices != vec![0] {
        return Err(format!(
            "unexpected rebuilt shard indexes: {rebuilt_indices:?}"
        ));
    }

    let mut under_width = vec![None; config.stripe_width()];
    under_width[0] = Some(encoded.shards[0].clone());
    let under_width_refusal = reconstruct_receipt_stripe(&config, &under_width);
    let (available, needed) = match under_width_refusal {
        Err(ReceiptStripeError::InsufficientShards { available, needed }) => (available, needed),
        other => return Err(format!("under-width EC set was not refused: {other:?}")),
    };
    Ok(json!({
        "profile": "local-helper-2-plus-1",
        "source_len": source.len(),
        "source_digest": digest(&source),
        "stripe_width": config.stripe_width(),
        "degraded_available_shards": 2,
        "rebuilt_shard_indexes": rebuilt_indices,
        "reconstructed_digest": digest(&reconstructed.payload[..source.len()]),
        "under_width_refused": true,
        "under_width_available": available,
        "under_width_needed": needed,
        "guest_elapsed_ns": elapsed_ns,
    }))
}

fn expect_invalid_available_set(
    config: &StripeConfig,
    available: &[Option<ErasureShard>],
    case: &str,
) -> Result<(), String> {
    match reconstruct_receipt_stripe(config, available) {
        Err(ReceiptStripeError::InvalidAvailableSet { slots, expected })
            if slots == available.len() && expected == config.stripe_width() =>
        {
            Ok(())
        }
        other => Err(format!(
            "malformed EC {case} was not refused as an invalid available set: {other:?}"
        )),
    }
}

fn ec_malformed_shard_set_refusal() -> Result<Value, String> {
    let source = payload()[..96].to_vec();
    let config = StripeConfig {
        data_shards: 2,
        parity_shards: 1,
        shard_len: 64,
    };
    let encoded = encode_receipt_stripe(&config, &source)
        .map_err(|error| format!("encode malformed-set fixture: {error:?}"))?;
    let available: Vec<_> = encoded.shards.into_iter().map(Some).collect();

    let wrong_width = available[..available.len() - 1].to_vec();
    expect_invalid_available_set(&config, &wrong_width, "wrong width")?;

    let mut wrong_index = available.clone();
    wrong_index[0]
        .as_mut()
        .expect("encoded shard must be present")
        .index = 1;
    expect_invalid_available_set(&config, &wrong_index, "slot/index mismatch")?;

    let mut wrong_role = available.clone();
    wrong_role[0]
        .as_mut()
        .expect("encoded shard must be present")
        .kind = ShardKind::Parity;
    expect_invalid_available_set(&config, &wrong_role, "slot/role mismatch")?;

    let mut wrong_length = available;
    wrong_length[0]
        .as_mut()
        .expect("encoded shard must be present")
        .bytes
        .pop();
    expect_invalid_available_set(&config, &wrong_length, "truncated shard")?;

    Ok(json!({
        "profile": "local-helper-2-plus-1",
        "expected_width": config.stripe_width(),
        "wrong_width_slots": wrong_width.len(),
        "wrong_width_refused": true,
        "wrong_index_refused": true,
        "wrong_role_refused": true,
        "truncated_shard_len": config.shard_len - 1,
        "truncated_shard_refused": true,
        "typed_refusal": "invalid-available-set",
        "generic_success_forbidden": true,
    }))
}

fn summary(rows: &[DataShapeRuntimeRow]) -> RuntimeSummary {
    let count = |status| rows.iter().filter(|row| row.status == status).count();
    let product_failed = count(ValidationStatus::ProductFail);
    let skipped = count(ValidationStatus::Skip);
    let status = if product_failed > 0 {
        ValidationStatus::ProductFail
    } else if skipped > 0 {
        ValidationStatus::Skip
    } else {
        ValidationStatus::Pass
    };
    RuntimeSummary {
        status,
        passed: count(ValidationStatus::Pass),
        product_failed,
        skipped,
    }
}

fn runtime_source(provenance: &DataShapeRunProvenance) -> RuntimeSource {
    RuntimeSource {
        carrier: provenance.carrier.clone(),
        kernel_release: provenance.kernel_release.clone(),
        command: COMMAND,
        code_paths: vec![
            "tidefs-compression encode/decode helpers",
            "tidefs-checksum-tree ObjectDigest",
            "tidefs-encryption extent AEAD helpers",
            "tidefs-erasure-coding receipt stripe helpers",
        ],
    }
}

fn report(
    provenance: &DataShapeRunProvenance,
    artifact_scope: &'static str,
    rows: Vec<DataShapeRuntimeRow>,
    non_claims: Vec<&'static str>,
    claim_effect: &'static str,
    residual_risk: Vec<&'static str>,
) -> DataShapeRuntimeReport {
    let summary = summary(&rows);
    DataShapeRuntimeReport {
        report_version: 2,
        claim_id: CLAIM_ID,
        issue: ISSUE_URL,
        run_id: provenance.run_id.clone(),
        source_ref: provenance.source_ref.clone(),
        generated_at: provenance.generated_at.clone(),
        validation_tier: ValidationTier::QemuGuest,
        command: COMMAND,
        artifact_scope,
        outcome: summary.status,
        runtime_execution_produced: summary.passed > 0,
        runtime_source: runtime_source(provenance),
        rows,
        summary,
        non_claims,
        claim_effect,
        residual_risk,
    }
}

fn mirrored_row(
    source_rows: &[DataShapeRuntimeRow],
    source_row: &'static str,
    row: &'static str,
    families: Vec<&'static str>,
    operation: &'static str,
    exact_boundary: &'static str,
) -> DataShapeRuntimeRow {
    let source = source_rows
        .iter()
        .find(|candidate| candidate.row == source_row)
        .expect("source runtime row must exist");
    DataShapeRuntimeRow {
        row,
        families,
        status: source.status,
        operation,
        observation: source.observation.clone(),
        exact_boundary,
    }
}

#[must_use]
pub fn build_runtime_reports(provenance: &DataShapeRunProvenance) -> DataShapeRuntimeReports {
    let transform_rows = vec![
        executed_row(
            "compression-zstd-helper-roundtrip",
            vec!["compression"],
            "encode and decode one deterministic Zstd helper frame",
            "Helper/library execution only; no mounted policy, receipt, raw-store, recovery, or source-retirement authority.",
            || compression_roundtrip(CompressionAlgorithm::Zstd),
        ),
        executed_row(
            "compression-lz4-helper-roundtrip",
            vec!["compression"],
            "encode and decode one deterministic LZ4 helper frame",
            "Helper/library execution only; no mounted policy, receipt, raw-store, recovery, or source-retirement authority.",
            || compression_roundtrip(CompressionAlgorithm::Lz4),
        ),
        executed_row(
            "stored-frame-digest-mismatch-refusal",
            vec!["digest-checksum", "compression"],
            "bind ObjectDigest to exact stored helper-frame bytes and reject one-byte mutation",
            "Domain-separated helper digest evidence only; no end-to-end mounted integrity, scrub, repair, or durable-media claim.",
            stored_frame_digest_refusal,
        ),
        executed_row(
            "malformed-compression-frame-refusal",
            vec!["compression", "digest-checksum"],
            "submit unknown-algorithm and truncated compression frames",
            "Typed compression helper refusal only; other transform-frame families remain unexecuted.",
            malformed_compression_refusal,
        ),
        executed_row(
            "encryption-aead-helper-roundtrip-refusal",
            vec!["encryption"],
            "encrypt/decrypt one extent helper frame and reject wrong-key and tampered ciphertext",
            "AEAD helper execution only; no key-epoch lifecycle, mounted dispatch, media reachability, cryptographic erase, or source-retirement proof.",
            encryption_roundtrip_and_refusal,
        ),
        executed_row(
            "ec-helper-degraded-reconstruction-under-width-refusal",
            vec!["erasure-coding"],
            "encode local 2+1 receipt stripe, reconstruct one missing shard, and refuse one-of-three under-width input",
            "Local EC helper execution only; no pool placement, distributed recovery, archive recall, availability, or degraded-read product claim.",
            ec_reconstruction_and_under_width_refusal,
        ),
        executed_row(
            "ec-helper-malformed-shard-set-refusal",
            vec!["erasure-coding"],
            "refuse wrong-width, wrong-index, wrong-role, and truncated local EC helper shard sets",
            "Local EC helper input validation only; no pool placement, repair receipt, archive, distributed recovery, availability, or degraded-read product claim.",
            ec_malformed_shard_set_refusal,
        ),
        skipped_row(
            "dedupe-domain-transform-execution",
            vec!["dedupe"],
            "deduplicate inside a legal domain and refuse illegal or unknown domains",
            "no runtime dedupe domain and reference-ownership path was executed",
            "Dedupe work remains owned outside this helper-validation slice.",
        ),
        skipped_row(
            "archive-recall-transform-execution",
            vec!["archive-shape"],
            "recall through declared archive media width and serving-role policy",
            "no archive media, retention, recall, or serving-role path was executed",
            "Local EC helper execution does not imply archive support.",
        ),
        skipped_row(
            "coalescing-transform-execution",
            vec!["coalescing"],
            "coalesce records with split/replay and source mapping",
            "no runtime coalescing implementation or receipt path was executed",
            "Coalescing and source retirement remain blocked.",
        ),
        skipped_row(
            "rebake-transform-execution",
            vec!["rebake"],
            "rebake old bytes into replacement authority with cutover and rollback receipts",
            "no rebake executor, cutover receipt, rollback, or source-retirement path was executed",
            "Placement, rebake, reclaim, and source-retirement work remains outside this slice.",
        ),
    ];

    let performance_rows = vec![
        executed_row(
            "guest-transform-elapsed-diagnostics",
            vec!["compression", "encryption", "erasure-coding"],
            "capture per-helper guest elapsed nanoseconds during actual execution",
            "Diagnostic elapsed observations only; they are not process CPU cost, a stable benchmark, an SLO, or comparator evidence.",
            || {
                Ok(json!({
                    "source_rows": transform_rows
                        .iter()
                        .filter(|row| row.status == ValidationStatus::Pass)
                        .map(|row| json!({
                            "row": row.row,
                            "guest_elapsed_ns": row.observation.get("guest_elapsed_ns"),
                        }))
                        .collect::<Vec<_>>(),
                }))
            },
        ),
        skipped_row(
            "cpu-cost",
            vec![
                "compression",
                "digest-checksum",
                "dedupe",
                "encryption",
                "ec-archive",
                "coalescing",
                "rebake",
            ],
            "measure process CPU cost under compiled policy with overload or refusal projection",
            "only single-run guest elapsed diagnostics were captured; process CPU attribution, workload matrix, and refusal budgets remain missing",
            "No performance or CPU-efficiency claim is permitted.",
        ),
        skipped_row(
            "read-amplification",
            vec!["compression", "dedupe", "ec-archive", "coalescing", "rebake"],
            "measure reads through the selected runtime path and caller-visible outcome",
            "no mounted or storage-owner read-amplification workload was executed",
            "Helper round trips do not measure mounted read amplification.",
        ),
        mirrored_row(
            &transform_rows,
            "ec-helper-degraded-reconstruction-under-width-refusal",
            "ec-helper-degraded-reconstruction",
            vec!["erasure-coding"],
            "reconstruct one missing local EC helper shard",
            "Local helper-only row; archive recall, pool receipts, distributed recovery, and degraded-read product visibility remain blocked.",
        ),
        skipped_row(
            "archive-degraded-reconstruction",
            vec!["archive-shape"],
            "recall or reconstruct archive media with degraded-visible result projection",
            "no archive media or recall path was executed",
            "The EC helper row cannot substitute for archive evidence.",
        ),
        mirrored_row(
            &transform_rows,
            "encryption-aead-helper-roundtrip-refusal",
            "encryption-wrong-key-tamper-refusal",
            vec!["encryption"],
            "reject a wrong in-memory helper key and tampered ciphertext",
            "Wrong-key helper refusal is not key-epoch lifecycle, mounted encryption, cryptographic erase, or media-remanence proof.",
        ),
        skipped_row(
            "key-epoch",
            vec!["encryption"],
            "bind active key epoch and refuse stale, retired, missing, or unauthorized epochs",
            "no persisted key epoch or lifecycle state was exercised",
            "Issue #1823 lifecycle authority remains outside this slice.",
        ),
        skipped_row(
            "illegal-dedupe-domain",
            vec!["dedupe"],
            "attempt cross-domain dedupe and preserve typed refusal",
            "no runtime dedupe domain was exercised",
            "Mounted dedupe and xfstests ownership remains outside this slice.",
        ),
        mirrored_row(
            &transform_rows,
            "malformed-compression-frame-refusal",
            "malformed-compression-frame",
            vec!["compression", "digest-checksum"],
            "reject unknown-algorithm and truncated compression helper frames",
            "This row covers compression helper frames only; encryption, coalescing, rebake, and mounted recovery frame faults remain incomplete.",
        ),
        mirrored_row(
            &transform_rows,
            "ec-helper-malformed-shard-set-refusal",
            "malformed-ec-shard-set",
            vec!["erasure-coding"],
            "reject wrong-width, wrong-index, wrong-role, and truncated local EC helper shard sets",
            "Typed local helper refusal only; no EC placement, repair, archive, distributed recovery, or degraded-read product authority.",
        ),
        mirrored_row(
            &transform_rows,
            "ec-helper-degraded-reconstruction-under-width-refusal",
            "ec-helper-under-width",
            vec!["erasure-coding"],
            "refuse one-of-three local EC helper input for a 2+1 profile",
            "Local helper refusal only; archive media and distributed placement widths remain unexecuted.",
        ),
        skipped_row(
            "archive-under-width",
            vec!["archive-shape"],
            "refuse under-width archive media or expose allowed degraded state",
            "no archive media, recall, or serving role was executed",
            "EC helper under-width refusal cannot substitute for archive evidence.",
        ),
        skipped_row(
            "coalescing-rebake-faults",
            vec!["coalescing", "rebake"],
            "inject split/replay, rollback, cutover, and source-retirement faults",
            "no coalescing or rebake executor was exercised",
            "Source-retirement and replacement-authority claims remain blocked.",
        ),
    ];

    DataShapeRuntimeReports {
        transform_execution: report(
            provenance,
            "QEMU-guest helper transform execution and exact refusal rows for a bounded subset of storage-intent data-shape families",
            transform_rows,
            vec![
                "not mounted transform authority",
                "not compiled-policy or receipt satisfaction",
                "not encryption key-lifecycle or cryptographic-erase proof",
                "not EC placement, archive, distributed recovery, or availability proof",
                "not dedupe, coalescing, rebake, reclaim, or source-retirement execution",
            ],
            "Actual helper execution now exists for compression, stored-frame digest rejection, AEAD refusal, and local EC reconstruction, under-width, and malformed-set refusal, but the registered evidence class and claim remain blocked on the skipped rows and end-to-end authority boundaries.",
            TRANSFORM_RESIDUAL_RISK.to_vec(),
        ),
        performance_fault: report(
            provenance,
            "QEMU-guest partial data-shape fault observations plus explicitly blocked performance and unexecuted family rows",
            performance_rows,
            vec![
                "not a stable CPU or read-amplification benchmark",
                "not a service objective or comparator row",
                "not mounted, archive, distributed, production, or release evidence",
            ],
            "Malformed compression and local EC shard-set refusals, wrong-key/tamper, and local EC under-width helper faults were executed, but CPU, read-amplification, key-epoch, dedupe-domain, archive, coalescing, and rebake rows keep this evidence class and claim blocked.",
            PERFORMANCE_RESIDUAL_RISK.to_vec(),
        ),
    }
}

fn serialize_report(report: &DataShapeRuntimeReport) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("encode data-shape runtime report: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn manifest_for(
    report: &DataShapeRuntimeReport,
    artifact_bytes: &[u8],
    artifact_path: &str,
    evidence_class: &str,
) -> Result<String, String> {
    let blocking_issues = if report.outcome == ValidationStatus::Pass {
        Vec::new()
    } else {
        vec![BlockingIssueRef {
            repo: Some("tidefs/tidefs".to_string()),
            number: 1981,
            reason: Some(
                "data-shape runtime evidence remains partial and the registered claim stays blocked"
                    .to_string(),
            ),
        }]
    };
    let manifest = EvidenceArtifactManifest {
        manifest_version: EVIDENCE_ARTIFACT_MANIFEST_VERSION,
        claim_id: CLAIM_ID.to_string(),
        evidence_class: evidence_class.to_string(),
        validation_tier: ValidationTier::QemuGuest,
        scope: format!(
            "{}; outcome={} pass={} product_fail={} skip={}",
            report.artifact_scope,
            report.outcome.label(),
            report.summary.passed,
            report.summary.product_failed,
            report.summary.skipped,
        ),
        artifact_path: artifact_path.to_string(),
        content_digest: content_digest_for_bytes(artifact_bytes),
        run_id: report.run_id.clone(),
        source_ref: report.source_ref.clone(),
        outcome: report.outcome,
        residual_risk: report.residual_risk.join(" "),
        source: SOURCE.to_string(),
        generated_at: report.generated_at.clone(),
        blocking_issues,
    };
    let mut json = manifest
        .to_json_pretty()
        .map_err(|error| error.to_string())?;
    json.push('\n');
    Ok(json)
}

pub fn write_runtime_evidence(
    output_dir: &Path,
    provenance: &DataShapeRunProvenance,
) -> Result<WrittenDataShapeEvidence, String> {
    fs::create_dir_all(output_dir)
        .map_err(|error| format!("create data-shape evidence output: {error}"))?;
    let reports = build_runtime_reports(provenance);
    let transform_bytes = serialize_report(&reports.transform_execution)?;
    let performance_bytes = serialize_report(&reports.performance_fault)?;
    let transform_manifest = manifest_for(
        &reports.transform_execution,
        &transform_bytes,
        TRANSFORM_ARTIFACT_PATH,
        "storage-intent-transform-execution-evidence",
    )?;
    let performance_manifest = manifest_for(
        &reports.performance_fault,
        &performance_bytes,
        PERFORMANCE_ARTIFACT_PATH,
        "storage-intent-data-shape-performance-fault-rows",
    )?;

    let written = WrittenDataShapeEvidence {
        transform_artifact: output_dir.join("data-shape-transform-execution.json"),
        transform_manifest: output_dir.join("data-shape-transform-execution.manifest.json"),
        performance_artifact: output_dir.join("data-shape-performance-fault-rows.json"),
        performance_manifest: output_dir.join("data-shape-performance-fault-rows.manifest.json"),
    };
    fs::write(&written.transform_artifact, transform_bytes)
        .map_err(|error| format!("write transform execution artifact: {error}"))?;
    fs::write(&written.transform_manifest, transform_manifest)
        .map_err(|error| format!("write transform execution manifest: {error}"))?;
    fs::write(&written.performance_artifact, performance_bytes)
        .map_err(|error| format!("write performance/fault artifact: {error}"))?;
    fs::write(&written.performance_manifest, performance_manifest)
        .map_err(|error| format!("write performance/fault manifest: {error}"))?;
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence_artifact_manifest::parse_evidence_artifact_manifest_json;

    fn provenance() -> DataShapeRunProvenance {
        DataShapeRunProvenance {
            run_id: "test-run/1".to_string(),
            source_ref: "0123456789abcdef".to_string(),
            generated_at: "2026-07-18T12:00:00Z".to_string(),
            carrier: "test-qemu-guest".to_string(),
            kernel_release: "7.0.0-test".to_string(),
        }
    }

    #[test]
    fn helper_rows_execute_but_claim_stays_blocked() {
        let reports = build_runtime_reports(&provenance());
        assert_eq!(
            reports.transform_execution.outcome(),
            ValidationStatus::Skip
        );
        assert!(reports.transform_execution.passed_rows() >= 7);
        assert!(reports.transform_execution.skipped_rows() >= 4);
        assert_eq!(reports.performance_fault.outcome(), ValidationStatus::Skip);
        assert!(reports.performance_fault.passed_rows() >= 6);
        assert!(reports.performance_fault.skipped_rows() >= 6);

        let malformed = reports
            .transform_execution
            .rows
            .iter()
            .find(|row| row.row == "ec-helper-malformed-shard-set-refusal")
            .expect("malformed EC shard-set row");
        assert_eq!(malformed.status, ValidationStatus::Pass);
        for field in [
            "wrong_width_refused",
            "wrong_index_refused",
            "wrong_role_refused",
            "truncated_shard_refused",
        ] {
            assert_eq!(malformed.observation[field].as_bool(), Some(true));
        }
    }

    #[test]
    fn written_manifests_are_qemu_scoped_and_digest_matched() {
        let output = tempfile::tempdir().expect("temporary output");
        let written = write_runtime_evidence(output.path(), &provenance()).expect("write evidence");
        for (artifact, manifest_path) in [
            (&written.transform_artifact, &written.transform_manifest),
            (&written.performance_artifact, &written.performance_manifest),
        ] {
            let manifest_text = fs::read_to_string(manifest_path).expect("read manifest");
            let manifest = parse_evidence_artifact_manifest_json(&manifest_text)
                .expect("parse evidence manifest");
            assert_eq!(manifest.validation_tier, ValidationTier::QemuGuest);
            assert_eq!(manifest.outcome, ValidationStatus::Skip);
            assert_eq!(manifest.blocking_issues[0].number, 1981);
            let artifact_bytes = fs::read(artifact).expect("read artifact");
            assert_eq!(
                manifest.content_digest,
                content_digest_for_bytes(&artifact_bytes)
            );
        }
    }
}
