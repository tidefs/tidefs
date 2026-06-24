// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Read-only storage-intent explanation rendering.
//!
//! This surface consumes supplied storage-intent core records and #913 query
//! snapshots. It deliberately does not scan topology, reopen pool state, or
//! infer missing producer evidence.

use std::fs;
use std::path::PathBuf;
use std::process;

use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use tidefs_storage_intent_core::{
    CostWearRecord, DataShapeRecord, DurabilityState, EvidenceFamilyFreshnessSet,
    EvidenceFamilyFreshnessState, LayoutAllocatorRecord, PrefetchResidencyDecisionRecord,
    ReadServingSourceClass, ReadSourceFreshnessRecord, RelocationLifecycleRecord,
    RelocationLifecycleState, SkippedMoveReason, StorageIntentEvidenceId,
    StorageIntentEvidenceKind, StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef,
    StorageIntentEvidenceRefs, StorageIntentGuaranteeClass, StorageIntentPolicy,
    StorageIntentReceipt, StorageIntentReceiptId, StorageIntentRefusal, StorageIntentRefusalReason,
    StorageMediaRole,
};

/// Storage-intent operator explanation commands.
#[derive(Subcommand, Debug)]
pub enum StorageIntentCommand {
    /// Explain supplied storage-intent evidence without changing placement
    Explain(StorageIntentExplainArgs),
}

/// `storage-intent explain [--input <json>] [--dataset <name>] [--json]`
#[derive(Args, Debug)]
pub struct StorageIntentExplainArgs {
    /// JSON evidence bundle containing storage-intent core records to render.
    #[arg(long = "input", value_name = "PATH")]
    pub input: Option<PathBuf>,

    /// Dataset label to show when the supplied bundle does not carry one.
    #[arg(long = "dataset", value_name = "DATASET")]
    pub dataset: Option<String>,

    /// File path label to show when the supplied bundle does not carry one.
    #[arg(long = "file", value_name = "PATH")]
    pub file: Option<String>,

    /// Byte range label to show when the supplied bundle does not carry one.
    #[arg(long = "range", value_name = "START..END")]
    pub range: Option<String>,

    /// Emit machine-parseable JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct ExplainSubject {
    #[serde(default)]
    dataset: Option<String>,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    range: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct StorageIntentExplainInput {
    #[serde(default)]
    subject: ExplainSubject,
    #[serde(default)]
    policy: Option<StorageIntentPolicy>,
    #[serde(default)]
    receipts: Vec<StorageIntentReceipt>,
    #[serde(default)]
    query_snapshot: Option<StorageIntentEvidenceQuerySnapshot>,
    #[serde(default)]
    refusals: Vec<StorageIntentRefusal>,
    #[serde(default)]
    read_freshness: Option<ReadSourceFreshnessRecord>,
    #[serde(default)]
    data_shape: Option<DataShapeRecord>,
    #[serde(default)]
    layout: Option<LayoutAllocatorRecord>,
    #[serde(default)]
    relocation: Option<RelocationLifecycleRecord>,
    #[serde(default)]
    cost_wear: Option<CostWearRecord>,
    #[serde(default)]
    prefetch_residency: Option<PrefetchResidencyDecisionRecord>,
}

#[derive(Debug, Serialize)]
struct ExplainReport {
    command: &'static str,
    input_source: String,
    subject: ExplainSubject,
    sections: Vec<ExplainSection>,
}

#[derive(Debug, Serialize)]
struct ExplainSection {
    name: &'static str,
    source: &'static str,
    availability: &'static str,
    facts: Vec<String>,
}

pub fn handle_storage_intent(cmd: StorageIntentCommand) {
    match cmd {
        StorageIntentCommand::Explain(args) => handle_explain(args),
    }
}

fn handle_explain(args: StorageIntentExplainArgs) {
    let (input, source) = read_input_or_default(&args);
    let subject = subject_from_args(&input.subject, &args);
    let report = build_report(&input, subject, source);

    if args.json {
        match serde_json::to_string_pretty(&report) {
            Ok(raw) => println!("{raw}"),
            Err(err) => {
                eprintln!("tidefsctl storage-intent explain: failed to format JSON: {err}");
                process::exit(1);
            }
        }
    } else {
        print!("{}", render_report_text(&report));
    }
}

fn read_input_or_default(args: &StorageIntentExplainArgs) -> (StorageIntentExplainInput, String) {
    match &args.input {
        Some(path) => {
            let raw = fs::read_to_string(path).unwrap_or_else(|err| {
                eprintln!(
                    "tidefsctl storage-intent explain: failed to read {}: {err}",
                    path.display()
                );
                process::exit(1);
            });
            let input = serde_json::from_str(&raw).unwrap_or_else(|err| {
                eprintln!(
                    "tidefsctl storage-intent explain: failed to parse {}: {err}",
                    path.display()
                );
                process::exit(1);
            });
            (input, format!("supplied-json:{}", path.display()))
        }
        None => (
            StorageIntentExplainInput::default(),
            "no-supplied-evidence".to_string(),
        ),
    }
}

fn subject_from_args(
    bundle_subject: &ExplainSubject,
    args: &StorageIntentExplainArgs,
) -> ExplainSubject {
    let mut subject = bundle_subject.clone();
    if let Some(dataset) = &args.dataset {
        subject.dataset = Some(dataset.clone());
    }
    if let Some(file) = &args.file {
        subject.file = Some(file.clone());
    }
    if let Some(range) = &args.range {
        subject.range = Some(range.clone());
    }
    subject
}

fn build_report(
    input: &StorageIntentExplainInput,
    subject: ExplainSubject,
    input_source: String,
) -> ExplainReport {
    let mut report = ExplainReport {
        command: "storage-intent explain",
        input_source,
        subject,
        sections: Vec::new(),
    };

    push_query_snapshot_section(&mut report, input.query_snapshot.as_ref());
    push_policy_section(&mut report, input.policy.as_ref());
    push_ack_section(&mut report, &input.receipts);
    push_placement_section(&mut report, &input.receipts);
    push_read_serving_section(
        &mut report,
        input.read_freshness.as_ref(),
        &input.receipts,
        input.prefetch_residency.as_ref(),
    );
    push_remote_lag_section(&mut report, input.read_freshness.as_ref(), &input.receipts);
    push_trust_section(&mut report, &input.receipts);
    push_volatility_section(&mut report, input.policy.as_ref(), &input.receipts);
    push_pending_work_section(&mut report, input.relocation.as_ref());
    push_data_shape_section(&mut report, input.data_shape.as_ref());
    push_layout_section(&mut report, input.layout.as_ref());
    push_prediction_section(&mut report, input.prefetch_residency.as_ref());
    push_cache_authority_section(
        &mut report,
        &input.receipts,
        input.prefetch_residency.as_ref(),
    );
    push_cost_wear_section(
        &mut report,
        input.cost_wear.as_ref(),
        input.relocation.as_ref(),
        input.query_snapshot.as_ref(),
    );
    push_refusal_section(
        &mut report,
        &input.refusals,
        input.query_snapshot.as_ref(),
        input.prefetch_residency.as_ref(),
        input.relocation.as_ref(),
    );

    report
}

fn render_report_text(report: &ExplainReport) -> String {
    let mut out = String::new();
    out.push_str("storage-intent explanation\n");
    out.push_str("  input-source: ");
    out.push_str(&report.input_source);
    out.push('\n');
    out.push_str("  subject: ");
    out.push_str(&subject_label(&report.subject));
    out.push('\n');

    for section in &report.sections {
        out.push('\n');
        out.push_str(section.name);
        out.push_str(" [");
        out.push_str(section.availability);
        out.push_str("; source: ");
        out.push_str(section.source);
        out.push_str("]\n");
        for fact in &section.facts {
            out.push_str("  - ");
            out.push_str(fact);
            out.push('\n');
        }
    }

    out
}

fn subject_label(subject: &ExplainSubject) -> String {
    let dataset = subject.dataset.as_deref().unwrap_or("unknown-dataset");
    let file = subject.file.as_deref().unwrap_or("unknown-file");
    let range = subject.range.as_deref().unwrap_or("unknown-range");
    format!("dataset={dataset} file={file} range={range}")
}

fn push_query_snapshot_section(
    report: &mut ExplainReport,
    snapshot: Option<&StorageIntentEvidenceQuerySnapshot>,
) {
    match snapshot {
        Some(snapshot) => {
            let mut facts = vec![
                format!("snapshot-id: {}", evidence_id(&snapshot.snapshot_id)),
                format!("query-id: {}", evidence_id(&snapshot.query_id)),
                format!("consumer: {}", snapshot.consumer.as_str()),
                format!("context: {}", snapshot.context.as_str()),
                format!("subject-scope: {}", snapshot.subject.scope_class.as_str()),
                format!("policy-revision: {}", snapshot.policy_revision.0),
                format!("completeness: {}", snapshot.completeness.as_str()),
                format!("retention: {}", snapshot.retention.as_str()),
                format!(
                    "frontiers: temporal={}ms freshness={}ms allowed-staleness={}ms",
                    snapshot.temporal_frontier_ms,
                    snapshot.freshness_frontier_ms,
                    snapshot.allowed_staleness_ms
                ),
                format!("source-catalog-ref: {}", evidence_ref(snapshot.source_catalog_ref)),
                format!("source-index-ref: {}", evidence_ref(snapshot.source_index_ref)),
                format!(
                    "visibility: non-authority-visible={} authority-admissible={}",
                    snapshot.allows_non_authority_visibility(),
                    snapshot.is_authority_admissible()
                ),
            ];
            push_evidence_refs(&mut facts, "included-ref", &snapshot.included_refs);
            push_family_freshness(&mut facts, &snapshot.family_freshness);
            if snapshot.refusal != StorageIntentRefusalReason::None {
                facts.push(format!("snapshot-refusal: {}", snapshot.refusal.as_str()));
            }

            report.sections.push(ExplainSection {
                name: "evidence-query-snapshot",
                source: "#913 supplied StorageIntentEvidenceQuerySnapshot",
                availability: availability_from_completeness(snapshot.completeness.as_str()),
                facts,
            });
        }
        None => push_unavailable(
            report,
            "evidence-query-snapshot",
            "#913 StorageIntentEvidenceQuerySnapshot",
            "unavailable: no supplied snapshot/refusal cut; multi-family explanation is non-authority and must not be replaced by topology scans",
        ),
    }
}

fn push_policy_section(report: &mut ExplainReport, policy: Option<&StorageIntentPolicy>) {
    match policy {
        Some(policy) => {
            let mut facts = vec![
                format!("policy-id: {}", policy_id(&policy.policy_id.0)),
                format!("revision: {}", policy.revision.0),
                format!("requested-guarantee: {}", policy.requested_guarantee.as_str()),
                format!(
                    "durability-request: min-state={} max-lag-ms={} allow-unknown-lag={}",
                    policy.durability.min_state.as_str(),
                    lag_bound(policy.durability.max_lag_ms),
                    policy.durability.allow_unknown_lag
                ),
                format!(
                    "media-authority-required: {} allowed-role-mask=0x{:x}",
                    policy.media.require_authority_role,
                    policy.media.allowed_roles.0
                ),
                format!(
                    "trust-floor: flags=0x{:x} session={} key-epoch>={}",
                    policy.trust.required_flags.0,
                    policy.trust.min_session_security.as_str(),
                    policy.trust.min_key_epoch
                ),
                format!(
                    "workload: shape={} confidence={} provenance={} evidence={}",
                    policy.workload.shape.as_str(),
                    policy.workload.confidence.as_str(),
                    policy.workload.provenance.as_str(),
                    evidence_ref(policy.workload.evidence)
                ),
            ];
            push_evidence_refs(&mut facts, "policy-evidence-ref", &policy.evidence_refs);
            report.sections.push(available(
                "requested-policy",
                "supplied StorageIntentPolicy",
                facts,
            ));
        }
        None => push_unavailable(
            report,
            "requested-policy",
            "#841 StorageIntentPolicy producer",
            "unavailable: no supplied policy record; requested, planned, and earned guarantees are not inferred",
        ),
    }
}

fn push_ack_section(report: &mut ExplainReport, receipts: &[StorageIntentReceipt]) {
    if receipts.is_empty() {
        push_unavailable(
            report,
            "earned-acknowledgment",
            "#841 StorageIntentReceipt producer",
            "unavailable: no supplied recent write/sync receipt; earned acknowledgment class is unknown",
        );
        return;
    }

    let facts = receipts
        .iter()
        .map(|receipt| {
            format!(
                "receipt {} earned ack {} for policy revision {} durability={} lag={}",
                receipt_id(receipt.receipt_id),
                receipt.ack_class.as_str(),
                receipt.policy_revision.0,
                receipt.durability.state.as_str(),
                receipt_lag(receipt)
            )
        })
        .collect();
    report.sections.push(available(
        "earned-acknowledgment",
        "supplied StorageIntentReceipt set",
        facts,
    ));
}

fn push_placement_section(report: &mut ExplainReport, receipts: &[StorageIntentReceipt]) {
    if receipts.is_empty() {
        push_unavailable(
            report,
            "placement-receipts",
            "#841 placement receipt producer",
            "unavailable: no supplied placement receipts; current byte/shard authority is unknown",
        );
        return;
    }

    let facts = receipts
        .iter()
        .map(|receipt| {
            format!(
                "receipt {} placement={} media={} role={} read-source={} authority={}",
                receipt_id(receipt.receipt_id),
                receipt.ack_class.as_str(),
                receipt.media_class.as_str(),
                receipt.media_role.as_str(),
                receipt.read_source.as_str(),
                authority_label(receipt.media_role, receipt.read_source)
            )
        })
        .collect();
    report.sections.push(available(
        "placement-receipts",
        "supplied StorageIntentReceipt set",
        facts,
    ));
}

fn push_read_serving_section(
    report: &mut ExplainReport,
    read_freshness: Option<&ReadSourceFreshnessRecord>,
    receipts: &[StorageIntentReceipt],
    decision: Option<&PrefetchResidencyDecisionRecord>,
) {
    let mut facts = Vec::new();
    if let Some(read_freshness) = read_freshness {
        facts.push(format!(
            "selected-source: {} source-receipt={} snapshot-generation={} freshness-frontier={}ms evidence={}",
            read_freshness.source.as_str(),
            receipt_id(read_freshness.source_receipt),
            read_freshness.snapshot_generation,
            read_freshness.freshness_frontier_ms,
            evidence_ref(read_freshness.evidence)
        ));
        facts.push(format!(
            "remote-or-geo-lag: {}",
            if read_freshness.lag_known {
                format!("{} ms", read_freshness.geo_lag_ms)
            } else {
                "unknown".to_string()
            }
        ));
    }
    for receipt in receipts {
        facts.push(format!(
            "receipt {} read-source={} action={}",
            receipt_id(receipt.receipt_id),
            receipt.read_source.as_str(),
            receipt.action_class.as_str()
        ));
    }
    if let Some(decision) = decision {
        facts.push(format!(
            "prefetch/residency decision selected {} outcome={} cache-only={} authority-change-candidate={}",
            decision.selected_candidate.as_str(),
            decision.outcome.as_str(),
            tidefs_storage_intent_core::prefetch_residency_decision_is_cache_only(*decision),
            tidefs_storage_intent_core::prefetch_residency_decision_may_request_authority_change(*decision)
        ));
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "read-serving",
            "#877/#913 read-serving evidence",
            "unavailable: no supplied read-serving freshness or decision record; cache/trial/remote/stale/degraded choices are unknown",
        );
    } else {
        report.sections.push(available(
            "read-serving",
            "supplied read freshness/receipt/decision records",
            facts,
        ));
    }
}

fn push_remote_lag_section(
    report: &mut ExplainReport,
    read_freshness: Option<&ReadSourceFreshnessRecord>,
    receipts: &[StorageIntentReceipt],
) {
    let mut facts = Vec::new();
    if let Some(read_freshness) = read_freshness {
        facts.push(format!(
            "read-source {} lag {}",
            read_freshness.source.as_str(),
            if read_freshness.lag_known {
                format!("{} ms", read_freshness.geo_lag_ms)
            } else {
                "unknown".to_string()
            }
        ));
    }
    for receipt in receipts.iter().filter(|receipt| {
        matches!(
            receipt.ack_class,
            StorageIntentGuaranteeClass::GeoAsync
                | StorageIntentGuaranteeClass::GeoIntent
                | StorageIntentGuaranteeClass::GeoFullPlacement
                | StorageIntentGuaranteeClass::RemoteVolatilePlusLocal
        ) || matches!(
            receipt.read_source,
            ReadServingSourceClass::RemoteReceipt | ReadServingSourceClass::GeoAsyncLag
        )
    }) {
        facts.push(format!(
            "receipt {} remote-class={} durability-lag={}",
            receipt_id(receipt.receipt_id),
            receipt.ack_class.as_str(),
            receipt_lag(receipt)
        ));
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "remote-rpo-lag",
            "#846/#913 transport and temporal evidence",
            "unavailable: no supplied remote path, RPO, or temporal evidence; stale age is unknown",
        );
    } else {
        report.sections.push(available(
            "remote-rpo-lag",
            "supplied read freshness/receipt records",
            facts,
        ));
    }
}

fn push_trust_section(report: &mut ExplainReport, receipts: &[StorageIntentReceipt]) {
    if receipts.is_empty() {
        push_unavailable(
            report,
            "trust-domain",
            "#897 trust/domain evidence",
            "unavailable: no supplied peer/domain/key/authorization evidence; remote/shared roles remain unknown or refused by consumers",
        );
        return;
    }

    let facts = receipts
        .iter()
        .map(|receipt| {
            format!(
                "receipt {} flags=0x{:x} session={} key-epoch={} residency={} sharing={} compromise={} quarantine={}",
                receipt_id(receipt.receipt_id),
                receipt.trust.flags.0,
                receipt.trust.session_security.as_str(),
                receipt.trust.key_epoch,
                receipt.trust.residency.as_str(),
                receipt.trust.sharing_domain.as_str(),
                receipt.trust.compromise_state.as_str(),
                receipt.trust.quarantine_state.as_str()
            )
        })
        .collect();
    report.sections.push(available(
        "trust-domain",
        "supplied receipt trust evidence state",
        facts,
    ));
}

fn push_volatility_section(
    report: &mut ExplainReport,
    policy: Option<&StorageIntentPolicy>,
    receipts: &[StorageIntentReceipt],
) {
    let mut facts = Vec::new();
    if let Some(policy) = policy {
        facts.push(format!(
            "requested minimum durability: {}",
            policy.durability.min_state.as_str()
        ));
    }
    for receipt in receipts {
        let volatile = matches!(receipt.durability.state, DurabilityState::Volatile)
            || matches!(
                receipt.media_role,
                StorageMediaRole::ScratchVolatile
                    | StorageMediaRole::ReadCache
                    | StorageMediaRole::RamCache
                    | StorageMediaRole::RamVolatileAuthority
            );
        if volatile {
            facts.push(format!(
                "volatile-visible: receipt {} role={} media={} loss-table=power-loss/process-loss/owner-loss may discard bytes unless another supplied durable receipt covers them",
                receipt_id(receipt.receipt_id),
                receipt.media_role.as_str(),
                receipt.media_class.as_str()
            ));
        }
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "volatility-loss",
            "#841 volatile receipt evidence",
            "unavailable: no supplied volatile receipt or policy record; unsafe/volatile state cannot be hidden or inferred",
        );
    } else {
        report.sections.push(available(
            "volatility-loss",
            "supplied policy/receipt records",
            facts,
        ));
    }
}

fn push_pending_work_section(
    report: &mut ExplainReport,
    relocation: Option<&RelocationLifecycleRecord>,
) {
    match relocation {
        Some(relocation) => {
            let availability = if relocation.state == RelocationLifecycleState::Complete {
                "available"
            } else {
                "limited"
            };
            report.sections.push(ExplainSection {
                name: "pending-work",
                source: "supplied RelocationLifecycleRecord",
                availability,
                facts: vec![format!(
                    "reason={} state={} source-receipt={} replacement-receipt={} skipped-reason={} evidence={}",
                    relocation.reason.as_str(),
                    relocation.state.as_str(),
                    receipt_id(relocation.source_receipt),
                    receipt_id(relocation.replacement_receipt),
                    relocation.cost_wear.skipped_reason.as_str(),
                    evidence_ref(relocation.evidence)
                )],
            });
        }
        None => push_unavailable(
            report,
            "pending-work",
            "#848 relocation/rebake/repair/evacuation evidence",
            "unavailable: no supplied relocation, rebake, repair, evacuation, or geo catch-up work record",
        ),
    }
}

fn push_data_shape_section(report: &mut ExplainReport, data_shape: Option<&DataShapeRecord>) {
    match data_shape {
        Some(data_shape) => report.sections.push(available(
            "data-shape",
            "#878 supplied DataShapeRecord",
            vec![format!(
                "record-size={} compression={} checksum={} ec={}/{} rebake-generation={} transform-refusal={} replacement-receipt={} evidence={}",
                data_shape.record_size_bytes,
                data_shape.compression_algorithm,
                data_shape.checksum_algorithm,
                data_shape.ec_data_shards,
                data_shape.ec_parity_shards,
                data_shape.rebake_generation,
                data_shape.transform_refusal.as_str(),
                receipt_id(data_shape.replacement_receipt),
                evidence_ref(data_shape.evidence)
            )],
        )),
        None => push_unavailable(
            report,
            "data-shape",
            "#878 data-shape evidence",
            "unavailable: no supplied transform, EC/archive shape, mounted transform block, or rebake progress record",
        ),
    }
}

fn push_layout_section(report: &mut ExplainReport, layout: Option<&LayoutAllocatorRecord>) {
    match layout {
        Some(layout) => report.sections.push(available(
            "layout-allocator",
            "#880 supplied LayoutAllocatorRecord",
            vec![format!(
                "allocation={} region={} fragmentation={}ppm locality={}ppm free-run-pressure={}ppm alignment={} zone-write-pointer={} pending-free={} pending-free-safe={} reclaim-debt={} stale-mirror-refusal={} evidence={}",
                layout.allocation_class.as_str(),
                layout.region_class.as_str(),
                layout.fragmentation_ppm,
                layout.locality_score_ppm,
                layout.free_run_pressure_ppm,
                layout.alignment_bytes,
                layout.zone_write_pointer,
                layout.pending_free_bytes,
                layout.pending_free_safe,
                layout.reclaim_debt_bytes,
                layout.stale_mirror_refusal,
                evidence_ref(layout.evidence)
            )],
        )),
        None => push_unavailable(
            report,
            "layout-allocator",
            "#880 layout/allocator evidence",
            "unavailable: no supplied allocator, fragmentation, locality, free-run, zone/write-pointer, pending-free, or reclaim-debt evidence",
        ),
    }
}

fn push_prediction_section(
    report: &mut ExplainReport,
    decision: Option<&PrefetchResidencyDecisionRecord>,
) {
    match decision {
        Some(decision) => report.sections.push(available(
            "prediction-residency",
            "#967 supplied PrefetchResidencyDecisionRecord",
            vec![format!(
                "policy-revision={} access-pattern={} confidence={} requested={} selected={} residency={} outcome={} refusal={} source-media={} target-media={} budget-owner={} max-prefetch-window={} max-staging={}",
                decision.policy_revision.0,
                decision.access_pattern.as_str(),
                decision.confidence.as_str(),
                decision.requested_candidate.as_str(),
                decision.selected_candidate.as_str(),
                decision.selected_residency.as_str(),
                decision.outcome.as_str(),
                decision.refusal.as_str(),
                decision.source_media.as_str(),
                decision.target_media.as_str(),
                domain_id(&decision.budget_owner.0),
                decision.max_prefetch_window_bytes,
                decision.max_staging_bytes
            )],
        )),
        None => push_unavailable(
            report,
            "prediction-residency",
            "#967/#913 prefetch/residency decision evidence",
            "unavailable: no supplied shadow, trial, admitted-move, cooldown, failed-payback, skipped-move, or residency decision record",
        ),
    }
}

fn push_cache_authority_section(
    report: &mut ExplainReport,
    receipts: &[StorageIntentReceipt],
    decision: Option<&PrefetchResidencyDecisionRecord>,
) {
    let mut facts = Vec::new();
    for receipt in receipts {
        facts.push(format!(
            "receipt {} state={} authority={}",
            receipt_id(receipt.receipt_id),
            cache_state_label(receipt.media_role, receipt.read_source),
            authority_label(receipt.media_role, receipt.read_source)
        ));
    }
    if let Some(decision) = decision {
        facts.push(format!(
            "decision selected-residency={} cache-only={} authority-change-candidate={}",
            decision.selected_residency.as_str(),
            tidefs_storage_intent_core::prefetch_residency_decision_is_cache_only(*decision),
            tidefs_storage_intent_core::prefetch_residency_decision_may_request_authority_change(
                *decision
            )
        ));
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "cache-vs-authority",
            "#841/#967 authority and cache evidence",
            "unavailable: no supplied receipt or residency decision; cache-only serving cannot be promoted to authority",
        );
    } else {
        report.sections.push(available(
            "cache-vs-authority",
            "supplied receipt/prefetch records",
            facts,
        ));
    }
}

fn push_cost_wear_section(
    report: &mut ExplainReport,
    cost_wear: Option<&CostWearRecord>,
    relocation: Option<&RelocationLifecycleRecord>,
    snapshot: Option<&StorageIntentEvidenceQuerySnapshot>,
) {
    let selected = cost_wear.or_else(|| relocation.map(|record| &record.cost_wear));
    let mut facts = Vec::new();
    if let Some(cost_wear) = selected {
        facts.push(cost_wear_fact(cost_wear));
    }
    if let Some(snapshot) = snapshot {
        push_reserve_family_fact(
            &mut facts,
            "critical-reserve capacity",
            &snapshot.family_freshness,
            StorageIntentEvidenceKind::CapacityAdmissionEvidence,
        );
        push_reserve_family_fact(
            &mut facts,
            "critical-reserve scheduler",
            &snapshot.family_freshness,
            StorageIntentEvidenceKind::SchedulerAdmissionRecord,
        );
        push_reserve_family_fact(
            &mut facts,
            "critical-reserve transport",
            &snapshot.family_freshness,
            StorageIntentEvidenceKind::TransportPathEvidence,
        );
        push_reserve_family_fact(
            &mut facts,
            "critical-reserve wear",
            &snapshot.family_freshness,
            StorageIntentEvidenceKind::MediaCostWearLedger,
        );
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "cost-wear-reserves",
            "#844/#856/#862/#898 cost, wear, reserve evidence",
            "unavailable: no supplied flash/network/capacity cost, movement debt, payback, or critical reserve evidence",
        );
    } else {
        report.sections.push(ExplainSection {
            name: "cost-wear-reserves",
            source: "supplied cost/wear records and #913 freshness states",
            availability: "limited",
            facts,
        });
    }
}

fn push_refusal_section(
    report: &mut ExplainReport,
    refusals: &[StorageIntentRefusal],
    snapshot: Option<&StorageIntentEvidenceQuerySnapshot>,
    decision: Option<&PrefetchResidencyDecisionRecord>,
    relocation: Option<&RelocationLifecycleRecord>,
) {
    let mut facts = Vec::new();
    for refusal in refusals {
        facts.push(format!(
            "policy-revision={} attempted-receipt={} reason={} evidence={}",
            refusal.policy_revision.0,
            receipt_id(refusal.attempted_receipt),
            refusal.reason.as_str(),
            evidence_ref(refusal.evidence)
        ));
    }
    if let Some(snapshot) = snapshot {
        if snapshot.refusal != StorageIntentRefusalReason::None {
            facts.push(format!(
                "snapshot refused evidence cut: {}",
                snapshot.refusal.as_str()
            ));
        }
    }
    if let Some(decision) = decision {
        if decision.refusal != StorageIntentRefusalReason::None {
            facts.push(format!(
                "prefetch/residency refused or lowered: outcome={} reason={}",
                decision.outcome.as_str(),
                decision.refusal.as_str()
            ));
        }
    }
    if let Some(relocation) = relocation {
        if relocation.cost_wear.skipped_reason != SkippedMoveReason::None {
            facts.push(format!(
                "relocation skipped: state={} reason={} payback-window={}ms cooldown-until={}ms",
                relocation.state.as_str(),
                relocation.cost_wear.skipped_reason.as_str(),
                relocation.cost_wear.payback_window_ms,
                relocation.cost_wear.cooldown_until_ms
            ));
        }
    }

    if facts.is_empty() {
        push_unavailable(
            report,
            "refusals",
            "#841/#913/#967 refusal evidence",
            "unavailable: no supplied stronger-guarantee refusal record; missing evidence remains unknown, not silently successful",
        );
    } else {
        report.sections.push(available(
            "refusals",
            "supplied refusal/snapshot/decision records",
            facts,
        ));
    }
}

fn push_unavailable(
    report: &mut ExplainReport,
    name: &'static str,
    source: &'static str,
    note: &'static str,
) {
    report.sections.push(ExplainSection {
        name,
        source,
        availability: "unavailable",
        facts: vec![note.to_string()],
    });
}

fn available(name: &'static str, source: &'static str, facts: Vec<String>) -> ExplainSection {
    ExplainSection {
        name,
        source,
        availability: "available",
        facts,
    }
}

fn availability_from_completeness(completeness: &'static str) -> &'static str {
    match completeness {
        "complete-for-purpose" => "available",
        "partial-admissible" => "limited",
        "degraded-visible" => "degraded-visible",
        "blocked" => "blocked",
        "refused" => "refused",
        "unsafe-visible" => "unsafe-visible",
        _ => "unknown",
    }
}

fn push_evidence_refs(facts: &mut Vec<String>, label: &str, refs: &StorageIntentEvidenceRefs) {
    let (entries, len) = refs.as_parts();
    if len == 0 {
        facts.push(format!("{label}: none-supplied"));
        return;
    }
    for entry in entries.iter().take(len as usize) {
        facts.push(format!("{label}: {}", evidence_ref(*entry)));
    }
}

fn push_family_freshness(facts: &mut Vec<String>, freshness: &EvidenceFamilyFreshnessSet) {
    let (families, len) = freshness.as_parts();
    if len == 0 {
        facts.push("family-freshness: none-supplied".to_string());
        return;
    }
    for family in families.iter().take(len as usize) {
        facts.push(format!(
            "family {}: state={} source-index-generation={} producer-generation={} frontier={}ms allowed-staleness={}ms ref={}",
            family.kind.as_str(),
            family.state.as_str(),
            family.source_index_generation,
            family.producer_generation,
            family.freshness_frontier_ms,
            family.allowed_staleness_ms,
            evidence_ref(family.evidence_ref)
        ));
    }
}

fn push_reserve_family_fact(
    facts: &mut Vec<String>,
    label: &str,
    freshness: &EvidenceFamilyFreshnessSet,
    kind: StorageIntentEvidenceKind,
) {
    let state = freshness.state_for_kind(kind);
    if state == EvidenceFamilyFreshnessState::Unknown {
        return;
    }
    facts.push(format!(
        "{label}: {} state={}",
        kind.as_str(),
        state.as_str()
    ));
}

fn cost_wear_fact(cost_wear: &CostWearRecord) -> String {
    format!(
        "movement-debt={} expected-write-bytes={} flash-wear={}ppm write-amplification={}ppm egress-cost={} capacity-cost={} payback-window={}ms payback-evidence={} cooldown-until={}ms skipped-reason={} evidence={}",
        cost_wear.movement_debt_bytes,
        cost_wear.expected_write_bytes,
        cost_wear.flash_wear_cost_ppm,
        cost_wear.write_amplification_ppm,
        cost_wear.egress_cost_microunits,
        cost_wear.capacity_cost_microunits,
        cost_wear.payback_window_ms,
        evidence_ref(cost_wear.payback_evidence),
        cost_wear.cooldown_until_ms,
        cost_wear.skipped_reason.as_str(),
        evidence_ref(cost_wear.evidence)
    )
}

fn receipt_lag(receipt: &StorageIntentReceipt) -> String {
    if receipt.durability.lag_known {
        format!("{} ms", receipt.durability.observed_lag_ms)
    } else {
        "unknown".to_string()
    }
}

fn lag_bound(value: u64) -> String {
    if value == u64::MAX {
        "unbounded".to_string()
    } else {
        value.to_string()
    }
}

fn authority_label(role: StorageMediaRole, read_source: ReadServingSourceClass) -> &'static str {
    if matches!(
        role,
        StorageMediaRole::ReadCache
            | StorageMediaRole::RamCache
            | StorageMediaRole::ScratchVolatile
            | StorageMediaRole::RepairTemp
            | StorageMediaRole::OptimizerTemp
    ) || matches!(
        read_source,
        ReadServingSourceClass::Cache | ReadServingSourceClass::ServingTrial
    ) {
        "not-authoritative"
    } else if matches!(role, StorageMediaRole::RamVolatileAuthority) {
        "volatile-authority"
    } else {
        "authoritative-placement"
    }
}

fn cache_state_label(role: StorageMediaRole, read_source: ReadServingSourceClass) -> &'static str {
    if matches!(
        role,
        StorageMediaRole::ReadCache
            | StorageMediaRole::RamCache
            | StorageMediaRole::ScratchVolatile
    ) || matches!(
        read_source,
        ReadServingSourceClass::Cache | ReadServingSourceClass::ServingTrial
    ) {
        "cache-only"
    } else if matches!(role, StorageMediaRole::RamVolatileAuthority) {
        "authoritative-volatile-ram"
    } else {
        "authoritative-placement"
    }
}

fn evidence_ref(reference: StorageIntentEvidenceRef) -> String {
    if reference.is_bound() {
        format!(
            "{}:{} generation={} version={}",
            reference.kind.as_str(),
            evidence_id(&reference.id),
            reference.generation,
            reference.version
        )
    } else {
        "unbound".to_string()
    }
}

fn receipt_id(id: StorageIntentReceiptId) -> String {
    if id == StorageIntentReceiptId::ZERO {
        "none".to_string()
    } else {
        hex_encode(&id.0)
    }
}

fn evidence_id(id: &StorageIntentEvidenceId) -> String {
    if *id == StorageIntentEvidenceId::ZERO {
        "none".to_string()
    } else {
        hex_encode(&id.0)
    }
}

fn policy_id(bytes: &[u8; 16]) -> String {
    if bytes.iter().all(|byte| *byte == 0) {
        "none".to_string()
    } else {
        hex_encode(bytes)
    }
}

fn domain_id(bytes: &[u8; 16]) -> String {
    policy_id(bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tidefs_storage_intent_core::{
        CostWearRecord, DurabilityReceiptState, DurabilityRequirement, DurabilityState,
        EvidenceCompletenessVerdict, EvidenceConsumerClass, EvidenceFamilyFreshness,
        EvidenceQueryContextClass, EvidenceQuerySubjectScope, EvidenceQuerySubjectScopeClass,
        MediaRoleMask, MediaRoleRequirement, PredictionConfidence, PrefetchResidencyCandidateClass,
        PrefetchResidencyDecisionOutcome, PrefetchResidencyStateClass, ReadSourceFreshnessRecord,
        RelocationLifecycleState, RelocationReasonClass, StorageIntentActionClass,
        StorageIntentDomainId, StorageIntentEvidenceRefs, StorageIntentObjectScope,
        StorageIntentPolicyId, StorageIntentPolicyRevision, StorageMediaClass, TrustEvidenceState,
        WorkloadPrediction, WorkloadShape,
    };

    fn id32(byte: u8) -> StorageIntentEvidenceId {
        StorageIntentEvidenceId([byte; 32])
    }

    fn id16(byte: u8) -> [u8; 16] {
        [byte; 16]
    }

    fn evidence(kind: StorageIntentEvidenceKind, byte: u8) -> StorageIntentEvidenceRef {
        StorageIntentEvidenceRef::new(kind, id32(byte), byte as u64, 1)
    }

    fn policy() -> StorageIntentPolicy {
        let mut refs = StorageIntentEvidenceRefs::EMPTY;
        refs.push(evidence(StorageIntentEvidenceKind::LocalIntentRecord, 1))
            .unwrap();
        StorageIntentPolicy {
            policy_id: StorageIntentPolicyId(id16(7)),
            revision: StorageIntentPolicyRevision(3),
            requested_guarantee: StorageIntentGuaranteeClass::LocalIntent,
            durability: DurabilityRequirement::DURABLE_INTENT_ZERO_LAG,
            media: MediaRoleRequirement {
                allowed_roles: MediaRoleMask::from_role(StorageMediaRole::PlacementAuthority),
                require_authority_role: true,
            },
            workload: WorkloadPrediction {
                shape: WorkloadShape::SyncSmallWrite,
                confidence: PredictionConfidence::High,
                evidence: evidence(StorageIntentEvidenceKind::WorkloadEvidence, 2),
                ..WorkloadPrediction::default()
            },
            evidence_refs: refs,
            ..StorageIntentPolicy::default()
        }
    }

    fn receipt(
        ack_class: StorageIntentGuaranteeClass,
        media_role: StorageMediaRole,
        media_class: StorageMediaClass,
        read_source: ReadServingSourceClass,
    ) -> StorageIntentReceipt {
        StorageIntentReceipt {
            receipt_id: StorageIntentReceiptId(id16(9)),
            policy_id: StorageIntentPolicyId(id16(7)),
            policy_revision: StorageIntentPolicyRevision(3),
            ack_class,
            durability: DurabilityReceiptState {
                state: if matches!(
                    ack_class,
                    StorageIntentGuaranteeClass::VolatileLocal
                        | StorageIntentGuaranteeClass::VolatileReplicated
                ) {
                    DurabilityState::Volatile
                } else {
                    DurabilityState::DurableIntent
                },
                observed_lag_ms: 0,
                lag_known: true,
            },
            trust: TrustEvidenceState {
                key_epoch: 4,
                ..TrustEvidenceState::default()
            },
            media_role,
            media_class,
            read_source,
            action_class: StorageIntentActionClass::NewWriteShaping,
            ..StorageIntentReceipt::default()
        }
    }

    fn snapshot() -> StorageIntentEvidenceQuerySnapshot {
        let mut included = StorageIntentEvidenceRefs::EMPTY;
        let mut freshness = tidefs_storage_intent_core::EvidenceFamilyFreshnessSet::EMPTY;
        for (kind, byte) in [
            (StorageIntentEvidenceKind::LocalIntentRecord, 11),
            (StorageIntentEvidenceKind::PlacementReceipt, 12),
            (StorageIntentEvidenceKind::CapacityAdmissionEvidence, 13),
            (StorageIntentEvidenceKind::SchedulerAdmissionRecord, 14),
            (StorageIntentEvidenceKind::TransportPathEvidence, 15),
            (StorageIntentEvidenceKind::MediaCostWearLedger, 16),
        ] {
            let reference = evidence(kind, byte);
            included.push(reference).unwrap();
            freshness
                .push(EvidenceFamilyFreshness {
                    kind,
                    state: EvidenceFamilyFreshnessState::Fresh,
                    source_index_generation: byte as u64,
                    producer_generation: byte as u64,
                    freshness_frontier_ms: 1000 + byte as u64,
                    allowed_staleness_ms: 50,
                    evidence_ref: reference,
                })
                .unwrap();
        }

        StorageIntentEvidenceQuerySnapshot {
            snapshot_id: id32(21),
            query_id: id32(22),
            consumer: EvidenceConsumerClass::OperatorExplanation,
            context: EvidenceQueryContextClass::OperatorExplanation,
            subject: EvidenceQuerySubjectScope {
                scope_class: EvidenceQuerySubjectScopeClass::Dataset,
                object_scope: StorageIntentObjectScope {
                    dataset_id: StorageIntentDomainId(id16(23)),
                    object_id: id32(24),
                    range_start: 0,
                    range_len: 4096,
                    generation: 1,
                },
                ..EvidenceQuerySubjectScope::default()
            },
            policy_id: StorageIntentPolicyId(id16(7)),
            policy_revision: StorageIntentPolicyRevision(3),
            temporal_frontier_ms: 1200,
            freshness_frontier_ms: 1200,
            allowed_staleness_ms: 50,
            source_catalog_ref: evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 25),
            source_index_ref: evidence(StorageIntentEvidenceKind::EvidenceQuerySnapshot, 26),
            source_index_generation: 2,
            producer_generation: 3,
            included_refs: included,
            family_freshness: freshness,
            completeness: EvidenceCompletenessVerdict::PartialAdmissible,
            ..StorageIntentEvidenceQuerySnapshot::default()
        }
    }

    fn text_for(input: StorageIntentExplainInput) -> String {
        let report = build_report(
            &input,
            ExplainSubject {
                dataset: Some("tank/fs".to_string()),
                file: Some("/file".to_string()),
                range: Some("0..4096".to_string()),
            },
            "test".to_string(),
        );
        render_report_text(&report)
    }

    #[test]
    fn durable_local_intent_reports_policy_ack_and_authority() {
        let text = text_for(StorageIntentExplainInput {
            policy: Some(policy()),
            receipts: vec![receipt(
                StorageIntentGuaranteeClass::LocalIntent,
                StorageMediaRole::PlacementAuthority,
                StorageMediaClass::NvmeFlash,
                ReadServingSourceClass::PlacementReceipt,
            )],
            query_snapshot: Some(snapshot()),
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("requested-guarantee: local-intent"));
        assert!(text.contains("earned ack local-intent"));
        assert!(text.contains("authoritative-placement"));
        assert!(text.contains("#913 supplied StorageIntentEvidenceQuerySnapshot"));
    }

    #[test]
    fn volatile_ram_intent_keeps_loss_table_visible() {
        let text = text_for(StorageIntentExplainInput {
            receipts: vec![receipt(
                StorageIntentGuaranteeClass::VolatileLocal,
                StorageMediaRole::RamVolatileAuthority,
                StorageMediaClass::SystemRam,
                ReadServingSourceClass::RamAuthority,
            )],
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("volatile-visible"));
        assert!(text.contains("loss-table=power-loss/process-loss/owner-loss"));
        assert!(text.contains("volatile-authority"));
    }

    #[test]
    fn geo_async_lag_is_reported_from_supplied_freshness() {
        let mut receipt = receipt(
            StorageIntentGuaranteeClass::GeoAsync,
            StorageMediaRole::GeoAsyncReplica,
            StorageMediaClass::CloudObject,
            ReadServingSourceClass::GeoAsyncLag,
        );
        receipt.durability.observed_lag_ms = 1200;
        let text = text_for(StorageIntentExplainInput {
            receipts: vec![receipt],
            read_freshness: Some(ReadSourceFreshnessRecord {
                source: ReadServingSourceClass::GeoAsyncLag,
                source_receipt: StorageIntentReceiptId(id16(9)),
                geo_lag_ms: 1200,
                lag_known: true,
                freshness_frontier_ms: 2000,
                evidence: evidence(StorageIntentEvidenceKind::ReadFreshnessEvidence, 31),
                ..ReadSourceFreshnessRecord::default()
            }),
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("geo-async"));
        assert!(text.contains("1200 ms"));
        assert!(text.contains("remote-rpo-lag"));
    }

    #[test]
    fn cache_only_serving_trial_is_not_authority() {
        let text = text_for(StorageIntentExplainInput {
            receipts: vec![receipt(
                StorageIntentGuaranteeClass::VolatileLocal,
                StorageMediaRole::ReadCache,
                StorageMediaClass::SystemRam,
                ReadServingSourceClass::ServingTrial,
            )],
            prefetch_residency: Some(PrefetchResidencyDecisionRecord {
                selected_candidate: PrefetchResidencyCandidateClass::CacheOnlyTrial,
                selected_residency: PrefetchResidencyStateClass::CacheOnlyRam,
                outcome: PrefetchResidencyDecisionOutcome::CacheOnly,
                ..PrefetchResidencyDecisionRecord::default()
            }),
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("cache-only"));
        assert!(text.contains("not-authoritative"));
        assert!(text.contains("cache-only"));
    }

    #[test]
    fn skipped_relocation_due_to_wear_payback_and_cooldown_is_visible() {
        let relocation = RelocationLifecycleRecord {
            reason: RelocationReasonClass::FlashServingPromotion,
            state: RelocationLifecycleState::Cooldown,
            cost_wear: CostWearRecord {
                movement_debt_bytes: 8192,
                expected_write_bytes: 16384,
                flash_wear_cost_ppm: 900_000,
                write_amplification_ppm: 3000,
                payback_window_ms: 60_000,
                cooldown_until_ms: 90_000,
                skipped_reason: SkippedMoveReason::FlashWearBudgetExceeded,
                payback_evidence: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 41),
                evidence: evidence(StorageIntentEvidenceKind::MediaCostWearLedger, 42),
                ..CostWearRecord::default()
            },
            evidence: evidence(StorageIntentEvidenceKind::RelocationReceipt, 43),
            ..RelocationLifecycleRecord::default()
        };
        let text = text_for(StorageIntentExplainInput {
            relocation: Some(relocation),
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("state=cooldown"));
        assert!(text.contains("flash-wear-budget-exceeded"));
        assert!(text.contains("movement-debt=8192"));
        assert!(text.contains("payback-window=60000ms"));
    }

    #[test]
    fn critical_reserve_protection_uses_snapshot_family_states() {
        let text = text_for(StorageIntentExplainInput {
            query_snapshot: Some(snapshot()),
            ..StorageIntentExplainInput::default()
        });

        assert!(text.contains("critical-reserve capacity"));
        assert!(text.contains("capacity-admission-evidence state=fresh"));
        assert!(text.contains("critical-reserve scheduler"));
        assert!(text.contains("critical-reserve transport"));
        assert!(text.contains("critical-reserve wear"));
    }

    #[test]
    fn missing_evidence_renders_source_qualified_unavailable() {
        let text = text_for(StorageIntentExplainInput::default());

        assert!(text.contains("evidence-query-snapshot [unavailable; source: #913"));
        assert!(text.contains("requested-policy [unavailable; source: #841"));
        assert!(text.contains("earned-acknowledgment [unavailable; source: #841"));
        assert!(text.contains("not inferred"));
    }
}
