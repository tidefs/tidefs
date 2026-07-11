// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Fail-closed release-readiness verdict assembly.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use tidefs_validation::evidence_artifact_manifest::{
    is_runtime_artifact_path, load_evidence_artifact_manifest_json_path,
};
use tidefs_validation::validation_schema::ValidationTier;

const SCHEMA_VERSION: u32 = 1;
const VERDICT_BOUNDARY: &str = "release-readiness-verdict";

const REQUIRED_EVIDENCE_FAMILIES: &[RequiredEvidenceFamilySpec] = &[
    RequiredEvidenceFamilySpec {
        id: "release-candidate-evidence-index",
        authority: "docs/RELEASE_CANDIDATE_EVIDENCE_CONTRACT.md",
        contract_status: "Defined evidence index; not a product-readiness claim.",
    },
    RequiredEvidenceFamilySpec {
        id: "claims-gate",
        authority: "docs/CLAIMS_GATE_POLICY.md, validation/claims.toml",
        contract_status: "Enforced claim registry; individual claims are not product admission.",
    },
    RequiredEvidenceFamilySpec {
        id: "claim-evidence-manifests",
        authority: "validation/claims.toml evidence_requirements",
        contract_status: "Claim receipts or evidence manifests must validate for current source.",
    },
    RequiredEvidenceFamilySpec {
        id: "performance-budget-gate",
        authority: "crates/tidefs-validation/src/performance_gate/",
        contract_status: "Gate-local perf_gate_ready receipt only.",
    },
    RequiredEvidenceFamilySpec {
        id: "standing-ci-gate",
        authority: "docs/GITHUB_CI.md",
        contract_status: "Standing self-hosted checks must pass for the verdict source.",
    },
    RequiredEvidenceFamilySpec {
        id: "operator-truth-surfaces",
        authority: "docs/RELEASE_READINESS_VERDICT_CONTRACT.md",
        contract_status: "Operator truth-surface evidence remains an open product gap.",
    },
    RequiredEvidenceFamilySpec {
        id: "operator-uapi-authority",
        authority: "docs/OPERATOR_UAPI_AUTHORITY.md",
        contract_status: "Pre-alpha command boundary does not create product admission.",
    },
    RequiredEvidenceFamilySpec {
        id: "transport-cluster-authority",
        authority: "TFR-017",
        contract_status: "Transport/cluster authority remains open.",
    },
    RequiredEvidenceFamilySpec {
        id: "unreleased-authority",
        authority: "docs/UNRELEASED_AUTHORITY_POLICY.md",
        contract_status: "Current policy guardrail; not release evidence by itself.",
    },
    RequiredEvidenceFamilySpec {
        id: "kernel-residency-evidence",
        authority: "docs/KERNEL_RESIDENT_POOL_ENGINE_ARCHITECTURE.md",
        contract_status: "Narrow kernel evidence exists; full daemonless coverage is not admitted.",
    },
    RequiredEvidenceFamilySpec {
        id: "explicit-non-claim-inputs",
        authority: "docs/RELEASE_READINESS_VERDICT_CONTRACT.md",
        contract_status: "Verdict must record explicit non-claims and residual risk.",
    },
];

#[derive(Clone, Debug)]
pub struct VerdictConfig {
    pub workspace_root: PathBuf,
    pub rc_index_path: PathBuf,
    pub claim_registry_path: PathBuf,
    pub source_ref: String,
    pub source_sha: String,
    pub run_id: String,
    pub output_path: PathBuf,
    pub non_claim_inputs_path: Option<PathBuf>,
    pub standing_ci_results_path: Option<PathBuf>,
    pub performance_gate_receipt_path: Option<PathBuf>,
}

#[derive(Debug)]
struct CliError {
    message: String,
    exit_code: i32,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 2,
        }
    }

    fn runtime(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            exit_code: 1,
        }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

pub fn run(args: impl Iterator<Item = String>) {
    match parse_args(args).and_then(write_verdict_artifact) {
        Ok(summary) => {
            eprintln!(
                "release-readiness verdict artifact written to {}: product_readiness_verdict={} gaps={}",
                summary.output_path.display(),
                summary.product_readiness_verdict,
                summary.open_gap_count
            );
        }
        Err(err) => {
            eprintln!("{err}");
            if err.exit_code == 2 {
                print_usage();
            }
            process::exit(err.exit_code);
        }
    }
}

#[derive(Debug)]
struct WriteSummary {
    output_path: PathBuf,
    product_readiness_verdict: &'static str,
    open_gap_count: usize,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<VerdictConfig, CliError> {
    let mut workspace_root = None;
    let mut rc_index_path = None;
    let mut claim_registry_path = None;
    let mut source_ref = None;
    let mut source_sha = None;
    let mut run_id = None;
    let mut output_path = None;
    let mut non_claim_inputs_path = None;
    let mut standing_ci_results_path = None;
    let mut performance_gate_receipt_path = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" | "help" => {
                print_usage();
                process::exit(0);
            }
            "--workspace-root" => workspace_root = Some(next_path(&mut args, "--workspace-root")?),
            "--rc-index" => rc_index_path = Some(next_path(&mut args, "--rc-index")?),
            "--claim-registry" => {
                claim_registry_path = Some(next_path(&mut args, "--claim-registry")?);
            }
            "--source-ref" => source_ref = Some(next_value(&mut args, "--source-ref")?),
            "--source-sha" => source_sha = Some(next_value(&mut args, "--source-sha")?),
            "--run-id" => run_id = Some(next_value(&mut args, "--run-id")?),
            "--output" => output_path = Some(next_path(&mut args, "--output")?),
            "--non-claim-inputs" => {
                non_claim_inputs_path = Some(next_path(&mut args, "--non-claim-inputs")?);
            }
            "--standing-ci-results" => {
                standing_ci_results_path = Some(next_path(&mut args, "--standing-ci-results")?);
            }
            "--performance-gate-receipt" => {
                performance_gate_receipt_path =
                    Some(next_path(&mut args, "--performance-gate-receipt")?);
            }
            other if other.starts_with('-') => {
                return Err(CliError::usage(format!("unknown option `{other}`")));
            }
            other => {
                return Err(CliError::usage(format!(
                    "unexpected positional argument `{other}`"
                )));
            }
        }
    }

    let config = VerdictConfig {
        workspace_root: require_path(workspace_root, "--workspace-root")?,
        rc_index_path: require_path(rc_index_path, "--rc-index")?,
        claim_registry_path: require_path(claim_registry_path, "--claim-registry")?,
        source_ref: require_text(source_ref, "--source-ref")?,
        source_sha: require_text(source_sha, "--source-sha")?,
        run_id: require_text(run_id, "--run-id")?,
        output_path: require_path(output_path, "--output")?,
        non_claim_inputs_path,
        standing_ci_results_path,
        performance_gate_receipt_path,
    };

    Ok(config)
}

fn next_path(
    args: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<PathBuf, CliError> {
    Ok(PathBuf::from(next_value(args, flag)?))
}

fn next_value(
    args: &mut impl Iterator<Item = String>,
    flag: &'static str,
) -> Result<String, CliError> {
    args.next()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::usage(format!("{flag} requires a non-empty value")))
}

fn require_path(value: Option<PathBuf>, flag: &'static str) -> Result<PathBuf, CliError> {
    value.ok_or_else(|| CliError::usage(format!("{flag} is required")))
}

fn require_text(value: Option<String>, flag: &'static str) -> Result<String, CliError> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| CliError::usage(format!("{flag} is required")))
}

fn print_usage() {
    eprintln!("usage: tidefs-xtask release-readiness-verdict \\");
    eprintln!("         --workspace-root PATH \\");
    eprintln!("         --rc-index PATH \\");
    eprintln!("         --claim-registry PATH \\");
    eprintln!("         --source-ref REF \\");
    eprintln!("         --source-sha SHA \\");
    eprintln!("         --run-id ID \\");
    eprintln!("         --output PATH \\");
    eprintln!("         [--non-claim-inputs PATH] \\");
    eprintln!("         [--standing-ci-results PATH] \\");
    eprintln!("         [--performance-gate-receipt PATH]");
}

fn write_verdict_artifact(config: VerdictConfig) -> Result<WriteSummary, CliError> {
    let artifact = assemble_verdict(&config);
    let json = serde_json::to_string_pretty(&artifact)
        .map_err(|err| CliError::runtime(format!("serialize verdict artifact: {err}")))?;
    if let Some(parent) = config.output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            CliError::runtime(format!(
                "create output directory {}: {err}",
                parent.display()
            ))
        })?;
    }
    fs::write(&config.output_path, json).map_err(|err| {
        CliError::runtime(format!(
            "write verdict artifact {}: {err}",
            config.output_path.display()
        ))
    })?;
    Ok(WriteSummary {
        output_path: config.output_path,
        product_readiness_verdict: artifact.product_readiness_verdict.as_str(),
        open_gap_count: artifact.open_gaps.len(),
    })
}

#[derive(Clone, Debug, Serialize)]
struct VerdictArtifact {
    schema_version: u32,
    verdict_boundary: &'static str,
    source: SourceIdentity,
    run_id: String,
    consumed_inputs: ConsumedInputs,
    required_evidence_families: Vec<RequiredEvidenceFamilyVerdict>,
    release_candidate_index: ReleaseCandidateVerdict,
    product_admission_gates: Vec<ProductAdmissionGateVerdict>,
    claim_evidence: Vec<ClaimVerdict>,
    ci_lane_results: Vec<CiLaneVerdict>,
    explicit_non_claims: ExplicitNonClaimVerdict,
    residual_risk: Vec<String>,
    open_gaps: Vec<OpenGap>,
    blocking_issues: Vec<BlockingIssueVerdict>,
    product_readiness_verdict: ProductReadinessVerdict,
}

#[derive(Clone, Debug, Serialize)]
struct SourceIdentity {
    source_ref: String,
    sha: String,
}

#[derive(Clone, Debug, Serialize)]
struct ConsumedInputs {
    release_candidate_evidence_index: InputDigest,
    claim_registry: InputDigest,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_claim_inputs: Option<InputDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    standing_ci_results: Option<InputDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    performance_gate_receipt: Option<InputDigest>,
}

#[derive(Clone, Debug, Serialize)]
struct InputDigest {
    path: String,
    outcome: VerdictOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<String>,
    details: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerdictOutcome {
    Pass,
    Blocked,
    Fail,
    Missing,
    Malformed,
    Stale,
    Partial,
}

impl VerdictOutcome {
    const fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    const fn as_registry_status(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Blocked => "blocked",
            Self::Fail => "fail",
            Self::Missing => "missing",
            Self::Malformed => "malformed",
            Self::Stale => "stale",
            Self::Partial => "partial",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProductReadinessVerdict {
    Ready,
    NotReady,
}

impl ProductReadinessVerdict {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotReady => "not_ready",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
struct RequiredEvidenceFamilyVerdict {
    family: &'static str,
    authority: &'static str,
    contract_status: &'static str,
    outcome: VerdictOutcome,
    details: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct RequiredEvidenceFamilySpec {
    id: &'static str,
    authority: &'static str,
    contract_status: &'static str,
}

#[derive(Clone, Debug, Serialize)]
struct ReleaseCandidateVerdict {
    path: String,
    outcome: VerdictOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow_run_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    product_readiness_boundary: Option<String>,
    lanes: Vec<CiLaneVerdict>,
    details: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CiLaneVerdict {
    id: String,
    outcome: VerdictOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    github_needs_result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    job_name: Option<String>,
    details: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ProductAdmissionGateVerdict {
    gate_id: String,
    outcome: VerdictOutcome,
    registry_status: String,
    scope: String,
    claim_ids: Vec<String>,
    required_evidence_classes: Vec<String>,
    authority_paths: Vec<String>,
    admission_rule: String,
    blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ClaimVerdict {
    claim_id: String,
    outcome: VerdictOutcome,
    registry_status: String,
    scope: String,
    required_evidence: Vec<ClaimEvidenceVerdict>,
    blockers: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ClaimEvidenceVerdict {
    class: String,
    outcome: VerdictOutcome,
    artifact_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    manifest_path: Option<String>,
    validation_tier: String,
    blocking_issues: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    residual_risk: Option<String>,
    details: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ExplicitNonClaimVerdict {
    outcome: VerdictOutcome,
    path: Option<String>,
    non_claims: Vec<String>,
    residual_risk: Vec<String>,
    details: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct OpenGap {
    family: String,
    outcome: VerdictOutcome,
    detail: String,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq, Ord, PartialOrd)]
struct BlockingIssueVerdict {
    repo: String,
    number: u64,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct ClaimRegistry {
    #[serde(default)]
    product_admission_gates: Vec<ProductAdmissionGateRecord>,
    #[serde(default)]
    claims: Vec<ClaimRecord>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProductAdmissionGateRecord {
    id: String,
    status: String,
    scope: String,
    #[serde(default)]
    claim_ids: Vec<String>,
    #[serde(default)]
    required_evidence_classes: Vec<String>,
    #[serde(default)]
    authority_paths: Vec<String>,
    admission_rule: String,
    #[serde(default)]
    blockers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimRecord {
    id: String,
    status: String,
    scope: String,
    #[serde(default)]
    required_evidence_classes: Vec<String>,
    #[serde(default)]
    evidence_requirements: Vec<ClaimEvidenceRequirement>,
    #[serde(default)]
    blockers: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ClaimEvidenceRequirement {
    class: String,
    path: String,
    validation_tier: String,
    #[serde(default)]
    manifest_path: Option<String>,
    #[serde(default)]
    blocking_issues: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseCandidateIndex {
    workflow: ReleaseCandidateWorkflow,
    source: ReleaseCandidateSource,
    profile: String,
    #[serde(default)]
    claim_boundary: ReleaseCandidateClaimBoundary,
    lanes: Vec<ReleaseCandidateLane>,
}

#[derive(Debug, Default, Deserialize)]
struct ReleaseCandidateClaimBoundary {
    #[serde(default)]
    product_readiness: Option<String>,
    #[serde(default)]
    lane_local_manifests_synthesized: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ReleaseCandidateWorkflow {
    run_id: String,
    #[serde(default)]
    run_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ReleaseCandidateSource {
    #[serde(default)]
    ref_name: Option<String>,
    #[serde(default)]
    r#ref: Option<String>,
    sha: String,
}

#[derive(Debug, Deserialize)]
struct ReleaseCandidateLane {
    id: String,
    #[serde(default)]
    job_name: Option<String>,
    #[serde(default)]
    github_needs_result: Option<String>,
    status: String,
}

#[derive(Debug, Deserialize)]
struct NonClaimInput {
    #[serde(default)]
    non_claims: Vec<String>,
    #[serde(default)]
    residual_risk: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct StandingCiResults {
    checks: Vec<StandingCiCheck>,
}

#[derive(Debug, Deserialize)]
struct StandingCiCheck {
    name: String,
    status: String,
    #[serde(default)]
    url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PerformanceGateReceiptProbe {
    perf_gate_ready: bool,
}

fn assemble_verdict(config: &VerdictConfig) -> VerdictArtifact {
    let rc_input = read_input_digest(&config.rc_index_path);
    let claim_registry_input = read_input_digest(&config.claim_registry_path);
    let non_claim_input = config
        .non_claim_inputs_path
        .as_ref()
        .map(|path| read_input_digest(path));
    let standing_ci_input = config
        .standing_ci_results_path
        .as_ref()
        .map(|path| read_input_digest(path));
    let perf_input = config
        .performance_gate_receipt_path
        .as_ref()
        .map(|path| read_input_digest(path));

    let release_candidate_index =
        evaluate_release_candidate_index(config, &config.rc_index_path, &rc_input);
    let registry = parse_claim_registry(&config.claim_registry_path).map_err(|err| err.to_string());
    let registry_outcome = match (&claim_registry_input.outcome, &registry) {
        (_, Ok(_)) => VerdictOutcome::Pass,
        (VerdictOutcome::Missing, Err(_)) => VerdictOutcome::Missing,
        (VerdictOutcome::Malformed, Err(_)) => VerdictOutcome::Malformed,
        (_, Err(_)) => VerdictOutcome::Malformed,
    };
    let (product_admission_gates, claim_evidence) = match registry {
        Ok(registry) => evaluate_claim_registry(config, &registry),
        Err(err) => (
            Vec::new(),
            vec![ClaimVerdict {
                claim_id: "claim-registry".to_string(),
                outcome: registry_outcome,
                registry_status: registry_outcome.as_registry_status().to_string(),
                scope: "validation/claims.toml".to_string(),
                required_evidence: Vec::new(),
                blockers: vec![err],
            }],
        ),
    };
    let standing_ci_results = evaluate_standing_ci(config.standing_ci_results_path.as_ref());
    let performance_gate = evaluate_performance_gate(config.performance_gate_receipt_path.as_ref());
    let explicit_non_claims = evaluate_non_claims(config.non_claim_inputs_path.as_ref());

    let mut ci_lane_results = release_candidate_index.lanes.clone();
    ci_lane_results.extend(standing_ci_results.iter().cloned());

    let mut family_outcomes = BTreeMap::new();
    family_outcomes.insert(
        "release-candidate-evidence-index",
        release_candidate_index.outcome,
    );
    family_outcomes.insert(
        "claims-gate",
        if !registry_outcome.is_pass() {
            registry_outcome
        } else if product_admission_gates
            .iter()
            .all(|gate| gate.outcome.is_pass())
            && !product_admission_gates.is_empty()
        {
            VerdictOutcome::Pass
        } else if product_admission_gates
            .iter()
            .any(|gate| gate.outcome == VerdictOutcome::Malformed)
        {
            VerdictOutcome::Malformed
        } else {
            VerdictOutcome::Blocked
        },
    );
    family_outcomes.insert(
        "claim-evidence-manifests",
        if !registry_outcome.is_pass() {
            registry_outcome
        } else if claim_evidence.iter().all(|claim| claim.outcome.is_pass())
            && !claim_evidence.is_empty()
        {
            VerdictOutcome::Pass
        } else if claim_evidence
            .iter()
            .any(|claim| claim.outcome == VerdictOutcome::Malformed)
        {
            VerdictOutcome::Malformed
        } else {
            VerdictOutcome::Blocked
        },
    );
    family_outcomes.insert("performance-budget-gate", performance_gate.outcome);
    family_outcomes.insert(
        "standing-ci-gate",
        if standing_ci_results
            .iter()
            .all(|lane| lane.outcome.is_pass())
            && !standing_ci_results.is_empty()
        {
            VerdictOutcome::Pass
        } else if standing_ci_results
            .iter()
            .any(|lane| lane.outcome == VerdictOutcome::Malformed)
        {
            VerdictOutcome::Malformed
        } else if standing_ci_results.is_empty() {
            VerdictOutcome::Missing
        } else {
            VerdictOutcome::Blocked
        },
    );
    family_outcomes.insert("explicit-non-claim-inputs", explicit_non_claims.outcome);

    for family in [
        "operator-truth-surfaces",
        "operator-uapi-authority",
        "transport-cluster-authority",
        "unreleased-authority",
        "kernel-residency-evidence",
    ] {
        family_outcomes.insert(family, VerdictOutcome::Blocked);
    }

    let required_evidence_families = REQUIRED_EVIDENCE_FAMILIES
        .iter()
        .map(|family| RequiredEvidenceFamilyVerdict {
            family: family.id,
            authority: family.authority,
            contract_status: family.contract_status,
            outcome: *family_outcomes
                .get(family.id)
                .unwrap_or(&VerdictOutcome::Missing),
            details: family_details(family.id),
        })
        .collect::<Vec<_>>();

    let mut residual_risk = explicit_non_claims.residual_risk.clone();
    residual_risk.push(
        "This verdict artifact is a fail-closed admission record, not a product release declaration."
            .to_string(),
    );
    residual_risk.sort();
    residual_risk.dedup();

    let mut open_gaps = Vec::new();
    collect_family_gaps(&required_evidence_families, &mut open_gaps);
    collect_release_candidate_gaps(&release_candidate_index, &mut open_gaps);
    collect_gate_gaps(&product_admission_gates, &mut open_gaps);
    collect_claim_gaps(&claim_evidence, &mut open_gaps);
    collect_non_claim_gaps(&explicit_non_claims, &mut open_gaps);
    collect_lane_gaps(&standing_ci_results, "standing-ci-gate", &mut open_gaps);
    if !performance_gate.outcome.is_pass() {
        open_gaps.push(OpenGap {
            family: "performance-budget-gate".to_string(),
            outcome: performance_gate.outcome,
            detail: performance_gate.details.join("; "),
        });
    }
    open_gaps.sort_by(|a, b| (a.family.as_str(), &a.detail).cmp(&(b.family.as_str(), &b.detail)));
    open_gaps.dedup_by(|a, b| a.family == b.family && a.detail == b.detail);

    let blocking_issues = collect_blocking_issues(&product_admission_gates, &claim_evidence);

    let product_readiness_verdict = if open_gaps.is_empty()
        && required_evidence_families
            .iter()
            .all(|family| family.outcome.is_pass())
    {
        ProductReadinessVerdict::Ready
    } else {
        ProductReadinessVerdict::NotReady
    };

    VerdictArtifact {
        schema_version: SCHEMA_VERSION,
        verdict_boundary: VERDICT_BOUNDARY,
        source: SourceIdentity {
            source_ref: config.source_ref.clone(),
            sha: config.source_sha.clone(),
        },
        run_id: config.run_id.clone(),
        consumed_inputs: ConsumedInputs {
            release_candidate_evidence_index: rc_input,
            claim_registry: claim_registry_input,
            non_claim_inputs: non_claim_input,
            standing_ci_results: standing_ci_input,
            performance_gate_receipt: perf_input,
        },
        required_evidence_families,
        release_candidate_index,
        product_admission_gates,
        claim_evidence,
        ci_lane_results,
        explicit_non_claims,
        residual_risk,
        open_gaps,
        blocking_issues,
        product_readiness_verdict,
    }
}

fn read_input_digest(path: &Path) -> InputDigest {
    match fs::read(path) {
        Ok(bytes) => InputDigest {
            path: path.display().to_string(),
            outcome: VerdictOutcome::Pass,
            digest: Some(format!("sha256:{}", hex::encode(Sha256::digest(&bytes)))),
            details: Vec::new(),
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => InputDigest {
            path: path.display().to_string(),
            outcome: VerdictOutcome::Missing,
            digest: None,
            details: vec![format!("input path is missing: {err}")],
        },
        Err(err) => InputDigest {
            path: path.display().to_string(),
            outcome: VerdictOutcome::Malformed,
            digest: None,
            details: vec![format!("input path could not be read: {err}")],
        },
    }
}

fn evaluate_release_candidate_index(
    config: &VerdictConfig,
    path: &Path,
    input: &InputDigest,
) -> ReleaseCandidateVerdict {
    if input.outcome == VerdictOutcome::Missing {
        return ReleaseCandidateVerdict {
            path: path.display().to_string(),
            outcome: VerdictOutcome::Missing,
            workflow_run_id: None,
            workflow_run_url: None,
            profile: None,
            source_ref: None,
            source_sha: None,
            product_readiness_boundary: None,
            lanes: Vec::new(),
            details: input.details.clone(),
        };
    }

    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return ReleaseCandidateVerdict {
                path: path.display().to_string(),
                outcome: VerdictOutcome::Malformed,
                workflow_run_id: None,
                workflow_run_url: None,
                profile: None,
                source_ref: None,
                source_sha: None,
                product_readiness_boundary: None,
                lanes: Vec::new(),
                details: vec![format!("cannot read release-candidate index: {err}")],
            };
        }
    };
    let index = match serde_json::from_str::<ReleaseCandidateIndex>(&text) {
        Ok(index) => index,
        Err(err) => {
            return ReleaseCandidateVerdict {
                path: path.display().to_string(),
                outcome: VerdictOutcome::Malformed,
                workflow_run_id: None,
                workflow_run_url: None,
                profile: None,
                source_ref: None,
                source_sha: None,
                product_readiness_boundary: None,
                lanes: Vec::new(),
                details: vec![format!("release-candidate index schema mismatch: {err}")],
            };
        }
    };

    let source_ref = index
        .source
        .r#ref
        .clone()
        .or_else(|| index.source.ref_name.clone())
        .unwrap_or_default();
    let mut details = Vec::new();
    if source_ref != config.source_ref {
        details.push(format!(
            "source ref mismatch: expected `{}`, index `{source_ref}`",
            config.source_ref
        ));
    }
    if index.source.sha != config.source_sha {
        details.push(format!(
            "source sha mismatch: expected `{}`, index `{}`",
            config.source_sha, index.source.sha
        ));
    }
    if index.profile != "full" {
        details.push(format!(
            "release-candidate profile `{}` is partial for whole-product verdict assembly",
            index.profile
        ));
    }
    if index.claim_boundary.product_readiness.as_deref() != Some("not_claimed") {
        details
            .push("release-candidate index did not preserve product_readiness=not_claimed".into());
    }
    if index.claim_boundary.lane_local_manifests_synthesized == Some(true) {
        details.push(
            "release-candidate index synthesized lane-local manifests; verdict boundary requires explicit inputs"
                .into(),
        );
    }

    let lanes = index
        .lanes
        .iter()
        .map(|lane| {
            let mut lane_details = Vec::new();
            let outcome = if lane.status == "run" {
                match lane.github_needs_result.as_deref() {
                    Some("success") => VerdictOutcome::Pass,
                    Some(result) => {
                        lane_details.push(format!(
                            "lane status `run` requires github_needs_result=success, got `{result}`"
                        ));
                        VerdictOutcome::Malformed
                    }
                    None => {
                        lane_details.push(
                            "lane status `run` is missing github_needs_result=success".to_string(),
                        );
                        VerdictOutcome::Malformed
                    }
                }
            } else if lane.status == "skipped_by_profile" {
                lane_details.push("lane skipped by selected profile".to_string());
                VerdictOutcome::Partial
            } else if lane.status == "failed" {
                lane_details.push("lane failed in release-candidate workflow".to_string());
                VerdictOutcome::Fail
            } else {
                lane_details.push(format!(
                    "lane status `{}` is not accepted by verdict boundary",
                    lane.status
                ));
                VerdictOutcome::Missing
            };
            CiLaneVerdict {
                id: lane.id.clone(),
                outcome,
                github_needs_result: lane.github_needs_result.clone(),
                status: Some(lane.status.clone()),
                job_name: lane.job_name.clone(),
                details: lane_details,
            }
        })
        .collect::<Vec<_>>();

    if lanes.is_empty() {
        details.push("release-candidate index has no lane results".to_string());
    }
    if lanes.iter().any(|lane| !lane.outcome.is_pass()) {
        details.push("one or more release-candidate lanes are not complete pass evidence".into());
    }

    let outcome = if details.iter().any(|detail| {
        detail.contains("source ref mismatch") || detail.contains("source sha mismatch")
    }) {
        VerdictOutcome::Stale
    } else if lanes.is_empty() {
        VerdictOutcome::Missing
    } else if lanes
        .iter()
        .any(|lane| lane.outcome == VerdictOutcome::Malformed)
    {
        VerdictOutcome::Malformed
    } else if lanes
        .iter()
        .any(|lane| lane.outcome == VerdictOutcome::Fail)
    {
        VerdictOutcome::Fail
    } else if lanes
        .iter()
        .any(|lane| lane.outcome == VerdictOutcome::Missing)
    {
        VerdictOutcome::Missing
    } else if details.is_empty() {
        VerdictOutcome::Pass
    } else {
        VerdictOutcome::Partial
    };

    ReleaseCandidateVerdict {
        path: path.display().to_string(),
        outcome,
        workflow_run_id: Some(index.workflow.run_id),
        workflow_run_url: index.workflow.run_url,
        profile: Some(index.profile),
        source_ref: Some(source_ref),
        source_sha: Some(index.source.sha),
        product_readiness_boundary: index.claim_boundary.product_readiness,
        lanes,
        details,
    }
}

fn parse_claim_registry(path: &Path) -> Result<ClaimRegistry, Box<dyn std::error::Error>> {
    let text = fs::read_to_string(path)?;
    let registry = toml::from_str::<ClaimRegistry>(&text)?;
    Ok(registry)
}

fn evaluate_claim_registry(
    config: &VerdictConfig,
    registry: &ClaimRegistry,
) -> (Vec<ProductAdmissionGateVerdict>, Vec<ClaimVerdict>) {
    let claim_map = registry
        .claims
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect::<BTreeMap<_, _>>();
    let gate_claim_ids = registry
        .product_admission_gates
        .iter()
        .flat_map(|gate| gate.claim_ids.iter().cloned())
        .collect::<BTreeSet<_>>();

    let gates = registry
        .product_admission_gates
        .iter()
        .map(|gate| {
            let outcome = gate_status_to_outcome(&gate.status);
            ProductAdmissionGateVerdict {
                gate_id: gate.id.clone(),
                outcome,
                registry_status: gate.status.clone(),
                scope: gate.scope.clone(),
                claim_ids: gate.claim_ids.clone(),
                required_evidence_classes: gate.required_evidence_classes.clone(),
                authority_paths: gate.authority_paths.clone(),
                admission_rule: gate.admission_rule.clone(),
                blockers: gate.blockers.clone(),
            }
        })
        .collect::<Vec<_>>();

    let claims = gate_claim_ids
        .iter()
        .map(|claim_id| match claim_map.get(claim_id.as_str()) {
            Some(claim) => evaluate_claim(config, claim),
            None => ClaimVerdict {
                claim_id: claim_id.clone(),
                outcome: VerdictOutcome::Missing,
                registry_status: "missing".to_string(),
                scope: "claim referenced by product-admission gate".to_string(),
                required_evidence: Vec::new(),
                blockers: vec!["product-admission gate references an unknown claim id".to_string()],
            },
        })
        .collect::<Vec<_>>();

    (gates, claims)
}

fn gate_status_to_outcome(status: &str) -> VerdictOutcome {
    match status {
        "validated" => VerdictOutcome::Pass,
        "blocked" | "planned" => VerdictOutcome::Blocked,
        "invalid" => VerdictOutcome::Fail,
        _ => VerdictOutcome::Malformed,
    }
}

fn evaluate_claim(config: &VerdictConfig, claim: &ClaimRecord) -> ClaimVerdict {
    let required_evidence = claim
        .required_evidence_classes
        .iter()
        .map(|class| evaluate_claim_evidence(config, claim, class))
        .collect::<Vec<_>>();

    let evidence_blocks = required_evidence
        .iter()
        .any(|evidence| !evidence.outcome.is_pass());
    let outcome = match claim.status.as_str() {
        "validated" if !evidence_blocks => VerdictOutcome::Pass,
        "validated" => VerdictOutcome::Fail,
        "blocked" | "planned" => VerdictOutcome::Blocked,
        "invalid" => VerdictOutcome::Fail,
        _ => VerdictOutcome::Malformed,
    };

    ClaimVerdict {
        claim_id: claim.id.clone(),
        outcome,
        registry_status: claim.status.clone(),
        scope: claim.scope.clone(),
        required_evidence,
        blockers: claim.blockers.clone(),
    }
}

fn evaluate_claim_evidence(
    config: &VerdictConfig,
    claim: &ClaimRecord,
    class: &str,
) -> ClaimEvidenceVerdict {
    let requirement = claim
        .evidence_requirements
        .iter()
        .find(|requirement| requirement.class == class);
    let Some(requirement) = requirement else {
        return ClaimEvidenceVerdict {
            class: class.to_string(),
            outcome: VerdictOutcome::Missing,
            artifact_path: String::new(),
            manifest_path: None,
            validation_tier: "unknown".to_string(),
            blocking_issues: Vec::new(),
            run_id: None,
            source_ref: None,
            evidence_outcome: None,
            residual_risk: None,
            details: vec![
                "claim registry does not define an evidence requirement for this class".to_string(),
            ],
        };
    };

    let mut details = Vec::new();
    let mut outcome = if requirement.blocking_issues.is_empty() {
        VerdictOutcome::Pass
    } else {
        details.push("evidence requirement names unresolved blocking issues".to_string());
        VerdictOutcome::Blocked
    };
    let mut run_id = None;
    let mut source_ref = None;
    let mut evidence_outcome = None;
    let mut residual_risk = None;

    if let Some(manifest_path) = &requirement.manifest_path {
        let absolute_manifest_path = config.workspace_root.join(manifest_path);
        match load_evidence_artifact_manifest_json_path(&absolute_manifest_path) {
            Ok(manifest) => {
                run_id = Some(manifest.run_id.clone());
                source_ref = Some(manifest.source_ref.clone());
                evidence_outcome = Some(manifest.outcome.label().to_string());
                residual_risk = Some(manifest.residual_risk.clone());

                if manifest.claim_id != claim.id {
                    details.push(format!(
                        "manifest claim_id `{}` does not match `{}`",
                        manifest.claim_id, claim.id
                    ));
                    outcome = VerdictOutcome::Malformed;
                }
                if manifest.evidence_class != class {
                    details.push(format!(
                        "manifest evidence_class `{}` does not match `{class}`",
                        manifest.evidence_class
                    ));
                    outcome = VerdictOutcome::Malformed;
                }
                if manifest.artifact_path != requirement.path {
                    details.push(format!(
                        "manifest artifact_path `{}` does not match registry path `{}`",
                        manifest.artifact_path, requirement.path
                    ));
                    outcome = VerdictOutcome::Malformed;
                }
                let manifest_validation_tier = manifest.validation_tier.label();
                if manifest_validation_tier != requirement.validation_tier {
                    details.push(format!(
                        "manifest validation_tier `{manifest_validation_tier}` does not match registry tier `{}`",
                        requirement.validation_tier
                    ));
                    outcome = VerdictOutcome::Malformed;
                }
                if manifest.source_ref != config.source_ref {
                    details.push(format!(
                        "manifest source_ref `{}` does not match verdict source `{}`",
                        manifest.source_ref, config.source_ref
                    ));
                    if outcome.is_pass() {
                        outcome = VerdictOutcome::Stale;
                    }
                }
                if !manifest.outcome.is_pass() {
                    details.push(format!(
                        "manifest outcome `{}` is not pass evidence",
                        manifest.outcome.label()
                    ));
                    if outcome.is_pass() {
                        outcome = VerdictOutcome::Fail;
                    }
                }
                if !manifest.blocking_issues.is_empty() {
                    details.push("manifest records unresolved blocking issues".to_string());
                    if outcome.is_pass() {
                        outcome = VerdictOutcome::Blocked;
                    }
                }

                match manifest.artifact_path_under(&config.workspace_root) {
                    Ok(artifact_path) if !artifact_path.exists() => {
                        details.push(format!(
                            "manifest artifact_path `{}` is missing",
                            artifact_path.display()
                        ));
                        if outcome.is_pass() {
                            outcome = VerdictOutcome::Missing;
                        }
                    }
                    Ok(_) => {
                        if let Err(err) = manifest.verify_artifact_digest(&config.workspace_root) {
                            details.push(format!("manifest artifact digest check failed: {err}"));
                            if outcome.is_pass() {
                                outcome = VerdictOutcome::Malformed;
                            }
                        }
                    }
                    Err(err) => {
                        details.push(format!("manifest artifact path is invalid: {err}"));
                        if outcome.is_pass() {
                            outcome = VerdictOutcome::Malformed;
                        }
                    }
                }
            }
            Err(err) => {
                details.push(format!(
                    "manifest `{}` could not be validated: {err}",
                    absolute_manifest_path.display()
                ));
                outcome = if absolute_manifest_path.exists() {
                    VerdictOutcome::Malformed
                } else {
                    VerdictOutcome::Missing
                };
            }
        }
    } else {
        if is_live_runtime_validation_tier(&requirement.validation_tier) {
            details.push(format!(
                "runtime-tier evidence requirement for class `{class}` must name manifest_path"
            ));
            outcome = VerdictOutcome::Malformed;
        } else if is_runtime_artifact_path(requirement.path.as_str()) {
            details.push(format!(
                "runtime artifact path `{}` for class `{class}` requires live-runtime validation_tier and manifest_path",
                requirement.path
            ));
            outcome = VerdictOutcome::Malformed;
        } else {
            let artifact_path = config.workspace_root.join(&requirement.path);
            if !artifact_path.exists() {
                details.push(format!(
                    "artifact path `{}` is missing",
                    artifact_path.display()
                ));
                if outcome.is_pass() {
                    outcome = VerdictOutcome::Missing;
                }
            }
        }
    }

    ClaimEvidenceVerdict {
        class: class.to_string(),
        outcome,
        artifact_path: requirement.path.clone(),
        manifest_path: requirement.manifest_path.clone(),
        validation_tier: requirement.validation_tier.clone(),
        blocking_issues: requirement.blocking_issues.clone(),
        run_id,
        source_ref,
        evidence_outcome,
        residual_risk,
        details,
    }
}

fn is_live_runtime_validation_tier(validation_tier: &str) -> bool {
    matches!(
        serde_json::from_value::<ValidationTier>(serde_json::Value::String(
            validation_tier.to_string()
        )),
        Ok(tier) if tier.is_live_runtime()
    )
}

fn evaluate_standing_ci(path: Option<&PathBuf>) -> Vec<CiLaneVerdict> {
    let Some(path) = path else {
        return Vec::new();
    };
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return vec![CiLaneVerdict {
                id: "standing-ci-results".to_string(),
                outcome: if err.kind() == std::io::ErrorKind::NotFound {
                    VerdictOutcome::Missing
                } else {
                    VerdictOutcome::Malformed
                },
                github_needs_result: None,
                status: None,
                job_name: None,
                details: vec![format!("cannot read standing CI results: {err}")],
            }];
        }
    };
    let results = match serde_json::from_str::<StandingCiResults>(&text) {
        Ok(results) => results,
        Err(err) => {
            return vec![CiLaneVerdict {
                id: "standing-ci-results".to_string(),
                outcome: VerdictOutcome::Malformed,
                github_needs_result: None,
                status: None,
                job_name: None,
                details: vec![format!("standing CI results schema mismatch: {err}")],
            }];
        }
    };

    results
        .checks
        .into_iter()
        .map(|check| {
            let status = check.status.to_ascii_lowercase();
            let mut details = Vec::new();
            if let Some(url) = &check.url {
                details.push(format!("url={url}"));
            }
            let outcome = match status.as_str() {
                "pass" | "passed" | "success" => VerdictOutcome::Pass,
                "fail" | "failed" | "failure" | "cancelled" | "timed_out" => VerdictOutcome::Fail,
                "pending" | "queued" | "in_progress" => VerdictOutcome::Missing,
                "blocked" => VerdictOutcome::Blocked,
                _ => VerdictOutcome::Malformed,
            };
            if !outcome.is_pass() {
                details.push(format!(
                    "standing CI check `{}` has status `{}`",
                    check.name, check.status
                ));
            }
            CiLaneVerdict {
                id: check.name.clone(),
                outcome,
                github_needs_result: None,
                status: Some(check.status),
                job_name: Some(check.name),
                details,
            }
        })
        .collect()
}

fn evaluate_performance_gate(path: Option<&PathBuf>) -> RequiredEvidenceFamilyVerdict {
    let Some(path) = path else {
        return RequiredEvidenceFamilyVerdict {
            family: "performance-budget-gate",
            authority: "crates/tidefs-validation/src/performance_gate/",
            contract_status: "Gate-local perf_gate_ready receipt only.",
            outcome: VerdictOutcome::Missing,
            details: vec!["no explicit performance-gate receipt path was provided".to_string()],
        };
    };
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return RequiredEvidenceFamilyVerdict {
                family: "performance-budget-gate",
                authority: "crates/tidefs-validation/src/performance_gate/",
                contract_status: "Gate-local perf_gate_ready receipt only.",
                outcome: if err.kind() == std::io::ErrorKind::NotFound {
                    VerdictOutcome::Missing
                } else {
                    VerdictOutcome::Malformed
                },
                details: vec![format!("cannot read performance-gate receipt: {err}")],
            };
        }
    };
    match serde_json::from_str::<PerformanceGateReceiptProbe>(&text) {
        Ok(receipt) if receipt.perf_gate_ready => RequiredEvidenceFamilyVerdict {
            family: "performance-budget-gate",
            authority: "crates/tidefs-validation/src/performance_gate/",
            contract_status: "Gate-local perf_gate_ready receipt only.",
            outcome: VerdictOutcome::Pass,
            details: vec!["perf_gate_ready=true".to_string()],
        },
        Ok(_) => RequiredEvidenceFamilyVerdict {
            family: "performance-budget-gate",
            authority: "crates/tidefs-validation/src/performance_gate/",
            contract_status: "Gate-local perf_gate_ready receipt only.",
            outcome: VerdictOutcome::Blocked,
            details: vec!["perf_gate_ready=false".to_string()],
        },
        Err(err) => RequiredEvidenceFamilyVerdict {
            family: "performance-budget-gate",
            authority: "crates/tidefs-validation/src/performance_gate/",
            contract_status: "Gate-local perf_gate_ready receipt only.",
            outcome: VerdictOutcome::Malformed,
            details: vec![format!("performance-gate receipt schema mismatch: {err}")],
        },
    }
}

fn evaluate_non_claims(path: Option<&PathBuf>) -> ExplicitNonClaimVerdict {
    let Some(path) = path else {
        return ExplicitNonClaimVerdict {
            outcome: VerdictOutcome::Missing,
            path: None,
            non_claims: Vec::new(),
            residual_risk: Vec::new(),
            details: vec!["no explicit non-claim input path was provided".to_string()],
        };
    };
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            return ExplicitNonClaimVerdict {
                outcome: if err.kind() == std::io::ErrorKind::NotFound {
                    VerdictOutcome::Missing
                } else {
                    VerdictOutcome::Malformed
                },
                path: Some(path.display().to_string()),
                non_claims: Vec::new(),
                residual_risk: Vec::new(),
                details: vec![format!("cannot read non-claim inputs: {err}")],
            };
        }
    };
    match serde_json::from_str::<NonClaimInput>(&text) {
        Ok(input) if input.non_claims.is_empty() || input.residual_risk.is_empty() => {
            ExplicitNonClaimVerdict {
                outcome: VerdictOutcome::Partial,
                path: Some(path.display().to_string()),
                non_claims: input.non_claims,
                residual_risk: input.residual_risk,
                details: vec![
                    "non-claim input must include both non_claims and residual_risk".to_string(),
                ],
            }
        }
        Ok(input) => ExplicitNonClaimVerdict {
            outcome: VerdictOutcome::Pass,
            path: Some(path.display().to_string()),
            non_claims: input.non_claims,
            residual_risk: input.residual_risk,
            details: Vec::new(),
        },
        Err(err) => ExplicitNonClaimVerdict {
            outcome: VerdictOutcome::Malformed,
            path: Some(path.display().to_string()),
            non_claims: Vec::new(),
            residual_risk: Vec::new(),
            details: vec![format!("non-claim input schema mismatch: {err}")],
        },
    }
}

fn family_details(family: &str) -> Vec<String> {
    match family {
        "operator-truth-surfaces" => vec![
            "operator truth-surface product properties are not admitted by current evidence"
                .to_string(),
        ],
        "operator-uapi-authority" => vec![
            "pre-alpha operator UAPI authority is not a runtime-fed product carrier".to_string(),
        ],
        "transport-cluster-authority" => {
            vec!["TFR-017 transport/cluster authority remains open".to_string()]
        }
        "unreleased-authority" => vec![
            "unreleased authority policy is a guardrail, not product admission evidence"
                .to_string(),
        ],
        "kernel-residency-evidence" => {
            vec!["full-kernel daemonless crash/replay coverage is not admitted".to_string()]
        }
        _ => Vec::new(),
    }
}

fn collect_family_gaps(families: &[RequiredEvidenceFamilyVerdict], open_gaps: &mut Vec<OpenGap>) {
    for family in families {
        if !family.outcome.is_pass() {
            open_gaps.push(OpenGap {
                family: family.family.to_string(),
                outcome: family.outcome,
                detail: if family.details.is_empty() {
                    family.contract_status.to_string()
                } else {
                    family.details.join("; ")
                },
            });
        }
    }
}

fn collect_release_candidate_gaps(rc: &ReleaseCandidateVerdict, open_gaps: &mut Vec<OpenGap>) {
    for detail in &rc.details {
        open_gaps.push(OpenGap {
            family: "release-candidate-evidence-index".to_string(),
            outcome: rc.outcome,
            detail: detail.clone(),
        });
    }
    for lane in &rc.lanes {
        if !lane.outcome.is_pass() {
            open_gaps.push(OpenGap {
                family: "release-candidate-evidence-index".to_string(),
                outcome: lane.outcome,
                detail: format!("lane `{}` is not pass evidence", lane.id),
            });
        }
    }
}

fn collect_gate_gaps(gates: &[ProductAdmissionGateVerdict], open_gaps: &mut Vec<OpenGap>) {
    for gate in gates {
        if !gate.outcome.is_pass() {
            let detail = if gate.blockers.is_empty() {
                format!(
                    "product-admission gate `{}` status is `{}`",
                    gate.gate_id, gate.registry_status
                )
            } else {
                format!(
                    "product-admission gate `{}` status is `{}`: {}",
                    gate.gate_id,
                    gate.registry_status,
                    gate.blockers.join("; ")
                )
            };
            open_gaps.push(OpenGap {
                family: "claims-gate".to_string(),
                outcome: gate.outcome,
                detail,
            });
        }
    }
}

fn collect_claim_gaps(claims: &[ClaimVerdict], open_gaps: &mut Vec<OpenGap>) {
    for claim in claims {
        if !claim.outcome.is_pass() {
            open_gaps.push(OpenGap {
                family: "claim-evidence-manifests".to_string(),
                outcome: claim.outcome,
                detail: format!(
                    "claim `{}` registry status is `{}`",
                    claim.claim_id, claim.registry_status
                ),
            });
        }
        for evidence in &claim.required_evidence {
            if !evidence.outcome.is_pass() {
                let detail = if evidence.details.is_empty() {
                    format!(
                        "claim `{}` evidence `{}` outcome is not pass",
                        claim.claim_id, evidence.class
                    )
                } else {
                    format!(
                        "claim `{}` evidence `{}`: {}",
                        claim.claim_id,
                        evidence.class,
                        evidence.details.join("; ")
                    )
                };
                open_gaps.push(OpenGap {
                    family: "claim-evidence-manifests".to_string(),
                    outcome: evidence.outcome,
                    detail,
                });
            }
        }
    }
}

fn collect_non_claim_gaps(non_claims: &ExplicitNonClaimVerdict, open_gaps: &mut Vec<OpenGap>) {
    if !non_claims.outcome.is_pass() {
        open_gaps.push(OpenGap {
            family: "explicit-non-claim-inputs".to_string(),
            outcome: non_claims.outcome,
            detail: non_claims.details.join("; "),
        });
    }
}

fn collect_lane_gaps(lanes: &[CiLaneVerdict], family: &str, open_gaps: &mut Vec<OpenGap>) {
    for lane in lanes {
        if !lane.outcome.is_pass() {
            open_gaps.push(OpenGap {
                family: family.to_string(),
                outcome: lane.outcome,
                detail: format!("CI lane `{}` outcome is not pass", lane.id),
            });
        }
    }
}

fn collect_blocking_issues(
    gates: &[ProductAdmissionGateVerdict],
    claims: &[ClaimVerdict],
) -> Vec<BlockingIssueVerdict> {
    let mut issues = BTreeSet::new();
    for gate in gates {
        for text in &gate.blockers {
            collect_issue_refs_from_text(text, &mut issues);
        }
    }
    for claim in claims {
        for text in &claim.blockers {
            collect_issue_refs_from_text(text, &mut issues);
        }
        for evidence in &claim.required_evidence {
            for issue in &evidence.blocking_issues {
                collect_issue_refs_from_text(issue, &mut issues);
            }
        }
    }
    issues.into_iter().collect()
}

fn collect_issue_refs_from_text(text: &str, issues: &mut BTreeSet<BlockingIssueVerdict>) {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'#' {
            index += 1;
            continue;
        }
        let start = index + 1;
        let mut end = start;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        if end > start {
            if let Ok(number) = text[start..end].parse::<u64>() {
                issues.insert(BlockingIssueVerdict {
                    repo: "tidefs/tidefs".to_string(),
                    number,
                    reason: text.to_string(),
                });
            }
        }
        index = end.max(index + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tidefs_validation::evidence_artifact_manifest::content_digest_for_path;

    #[test]
    fn release_readiness_missing_rc_index_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_claim_registry("validated");
        fixture.write_non_claim_inputs();
        let artifact = assemble_verdict(&fixture.config_with_rc("missing/index.json"));

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert_eq!(
            artifact.release_candidate_index.outcome,
            VerdictOutcome::Missing
        );
        assert!(artifact
            .open_gaps
            .iter()
            .any(|gap| gap.family == "release-candidate-evidence-index"));
    }

    #[test]
    fn release_readiness_malformed_rc_lane_result_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_rc_index_with_rust_result(
            &fixture.source_ref,
            &fixture.source_sha,
            "full",
            "failure",
        );
        fixture.write_claim_registry("validated");
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert_eq!(
            artifact.release_candidate_index.outcome,
            VerdictOutcome::Malformed
        );
        assert!(artifact
            .release_candidate_index
            .lanes
            .iter()
            .any(|lane| lane.id == "rust-smoke"
                && lane.outcome == VerdictOutcome::Malformed
                && lane
                    .details
                    .iter()
                    .any(|detail| detail.contains("github_needs_result=success"))));
    }

    #[test]
    fn release_readiness_pass_shaped_blocked_claims_stay_not_ready() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "full");
        fixture.write_pass_manifest("storage.intent.successor_comparator.v1");
        fixture.write_claim_registry("blocked");
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert!(artifact
            .product_admission_gates
            .iter()
            .any(
                |gate| gate.registry_status == "blocked" && gate.outcome == VerdictOutcome::Blocked
            ));
        assert!(artifact
            .claim_evidence
            .iter()
            .any(|claim| claim.registry_status == "blocked"
                && claim.outcome == VerdictOutcome::Blocked));
    }

    #[test]
    fn release_readiness_manifest_validation_tier_mismatch_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "full");
        fixture.write_pass_manifest_with_validation_tier(
            "storage.intent.successor_comparator.v1",
            "cargo-unit",
        );
        fixture.write_claim_registry("validated");
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert!(artifact
            .claim_evidence
            .iter()
            .any(
                |claim| claim.required_evidence.iter().any(|evidence| evidence.class
                    == "claims-gate-review"
                    && evidence.outcome == VerdictOutcome::Malformed
                    && evidence
                        .details
                        .iter()
                        .any(|detail| detail.contains("validation_tier")))
            ));
    }

    #[test]
    fn release_readiness_runtime_requirement_without_manifest_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "full");
        let artifact_path = fixture
            .temp
            .path()
            .join("validation/artifacts/test/claims-gate-review.json");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, r#"{"decision":"pass"}"#).unwrap();
        fixture.write_claim_registry_with_requirement("validated", "mounted-userspace", None);
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert!(artifact
            .claim_evidence
            .iter()
            .any(
                |claim| claim.required_evidence.iter().any(|evidence| evidence.class
                    == "claims-gate-review"
                    && evidence.outcome == VerdictOutcome::Malformed
                    && evidence
                        .details
                        .iter()
                        .any(|detail| detail.contains("runtime-tier")
                            && detail.contains("manifest_path")))
            ));
    }

    #[test]
    fn release_readiness_kbuild_requirement_without_manifest_is_code_only() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "full");
        let artifact_path = fixture
            .temp
            .path()
            .join("validation/artifacts/test/claims-gate-review.json");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, r#"{"decision":"pass"}"#).unwrap();
        fixture.write_claim_registry_with_requirement("validated", "kbuild", None);
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert!(artifact.claim_evidence.iter().any(|claim| {
            claim.required_evidence.iter().any(|evidence| {
                evidence.class == "claims-gate-review"
                    && evidence.validation_tier == "kbuild"
                    && evidence.outcome == VerdictOutcome::Pass
                    && evidence
                        .details
                        .iter()
                        .all(|detail| !detail.contains("manifest_path"))
            })
        }));
    }

    #[test]
    fn release_readiness_runtime_artifact_path_without_manifest_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "full");
        let artifact_path = fixture
            .temp
            .path()
            .join("validation/artifacts/test/claims-gate-review-runtime.json");
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(&artifact_path, r#"{"decision":"pass"}"#).unwrap();
        fixture.write_claim_registry_with_requirement_path(
            "validated",
            "source-model",
            "validation/artifacts/test/claims-gate-review-runtime.json",
            None,
        );
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert!(artifact.claim_evidence.iter().any(|claim| {
            claim.required_evidence.iter().any(|evidence| {
                evidence.class == "claims-gate-review"
                    && evidence.outcome == VerdictOutcome::Malformed
                    && evidence.details.iter().any(|detail| {
                        detail.contains("runtime artifact path")
                            && detail.contains("live-runtime")
                            && detail.contains("manifest_path")
                    })
            })
        }));
    }

    #[test]
    fn release_readiness_stale_source_ref_fails_closed() {
        let fixture = Fixture::new();
        fixture.write_rc_index("refs/heads/other", &fixture.source_sha, "full");
        fixture.write_claim_registry("validated");
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert_eq!(
            artifact.release_candidate_index.outcome,
            VerdictOutcome::Stale
        );
        assert!(artifact
            .release_candidate_index
            .details
            .iter()
            .any(|detail| detail.contains("source ref mismatch")));
    }

    #[test]
    fn release_readiness_current_all_gates_blocked_output_is_not_ready() {
        let fixture = Fixture::new();
        fixture.write_rc_index(&fixture.source_ref, &fixture.source_sha, "smoke");
        fixture.write_claim_registry("blocked");
        fixture.write_non_claim_inputs();

        let artifact = assemble_verdict(&fixture.config());

        assert_eq!(artifact.schema_version, SCHEMA_VERSION);
        assert_eq!(artifact.verdict_boundary, VERDICT_BOUNDARY);
        assert_eq!(
            artifact.product_readiness_verdict,
            ProductReadinessVerdict::NotReady
        );
        assert!(artifact
            .required_evidence_families
            .iter()
            .any(|family| family.family == "claims-gate"
                && family.outcome == VerdictOutcome::Blocked));
        assert!(!artifact.open_gaps.is_empty());
    }

    struct Fixture {
        temp: TempDir,
        source_ref: String,
        source_sha: String,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().expect("tempdir");
            fs::create_dir_all(temp.path().join("validation/artifacts/test")).unwrap();
            Self {
                temp,
                source_ref: "refs/heads/gpt4/issue-1772-release-readiness-verdict".to_string(),
                source_sha: "0123456789abcdef0123456789abcdef01234567".to_string(),
            }
        }

        fn config(&self) -> VerdictConfig {
            self.config_with_rc("release-candidate-evidence-index/index.json")
        }

        fn config_with_rc(&self, rc_index: &str) -> VerdictConfig {
            VerdictConfig {
                workspace_root: self.temp.path().to_path_buf(),
                rc_index_path: self.temp.path().join(rc_index),
                claim_registry_path: self.temp.path().join("validation/claims.toml"),
                source_ref: self.source_ref.clone(),
                source_sha: self.source_sha.clone(),
                run_id: "verdict-run-1".to_string(),
                output_path: self.temp.path().join("verdict.json"),
                non_claim_inputs_path: Some(self.temp.path().join("non-claims.json")),
                standing_ci_results_path: None,
                performance_gate_receipt_path: None,
            }
        }

        fn write_rc_index(&self, source_ref: &str, source_sha: &str, profile: &str) {
            self.write_rc_index_with_rust_result(source_ref, source_sha, profile, "success");
        }

        fn write_rc_index_with_rust_result(
            &self,
            source_ref: &str,
            source_sha: &str,
            profile: &str,
            rust_needs_result: &str,
        ) {
            let path = self
                .temp
                .path()
                .join("release-candidate-evidence-index/index.json");
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            let skipped = if profile == "smoke" {
                r#""status":"skipped_by_profile","github_needs_result":"skipped""#
            } else {
                r#""status":"run","github_needs_result":"success""#
            };
            let json = format!(
                r#"{{
  "schema_version": 1,
  "workflow": {{
    "name": "Release Candidate",
    "run_id": "12345",
    "run_url": "https://github.com/tidefs/tidefs/actions/runs/12345"
  }},
  "source": {{
    "repository": "tidefs/tidefs",
    "ref": "{source_ref}",
    "ref_name": "fixture",
    "sha": "{source_sha}"
  }},
  "profile": "{profile}",
  "claim_boundary": {{
    "product_readiness": "not_claimed",
    "lane_local_manifests_synthesized": false
  }},
  "lanes": [
    {{"id":"rust-smoke","job_name":"Rust smoke","github_needs_result":"{rust_needs_result}","status":"run"}},
    {{"id":"nix","job_name":"Nix","github_needs_result":"success","status":"run"}},
    {{"id":"qemu","job_name":"QEMU","github_needs_result":"success","status":"run"}},
    {{"id":"xfstests","job_name":"xfstests",{skipped}}},
    {{"id":"rdma","job_name":"RDMA",{skipped}}}
  ]
}}"#
            );
            fs::write(path, json).unwrap();
        }

        fn write_claim_registry(&self, status: &str) {
            self.write_claim_registry_with_requirement(
                status,
                "source-model",
                Some("validation/artifacts/test/claims-gate-review.manifest.json"),
            );
        }

        fn write_claim_registry_with_requirement(
            &self,
            status: &str,
            validation_tier: &str,
            manifest_path: Option<&str>,
        ) {
            self.write_claim_registry_with_requirement_path(
                status,
                validation_tier,
                "validation/artifacts/test/claims-gate-review.json",
                manifest_path,
            );
        }

        fn write_claim_registry_with_requirement_path(
            &self,
            status: &str,
            validation_tier: &str,
            path: &str,
            manifest_path: Option<&str>,
        ) {
            let manifest_path = manifest_path
                .map(|manifest_path| format!(r#", manifest_path = "{manifest_path}""#))
                .unwrap_or_default();
            let registry = format!(
                r#"
[[product_admission_gates]]
id = "fixture-gate"
status = "{status}"
scope = "fixture product gate"
claim_ids = ["storage.intent.successor_comparator.v1"]
required_evidence_classes = ["claims-gate-review"]
authority_paths = ["validation/claims.toml"]
admission_rule = "Fixture gate validates only when the claim validates."
blockers = ["Fixture blocker #1772"]

[[claims]]
id = "storage.intent.successor_comparator.v1"
status = "{status}"
scope = "fixture claim"
required_evidence_classes = ["claims-gate-review"]
evidence_requirements = [
  {{ class = "claims-gate-review", path = "{path}", validation_tier = "{validation_tier}"{manifest_path}, blocking_issues = [] }},
]
blockers = ["Fixture claim remains blocked #1740"]
generated_doc = "Fixture wording"
"#
            );
            fs::create_dir_all(self.temp.path().join("validation")).unwrap();
            fs::write(self.temp.path().join("validation/claims.toml"), registry).unwrap();
        }

        fn write_pass_manifest(&self, claim_id: &str) {
            self.write_pass_manifest_with_validation_tier(claim_id, "source-model");
        }

        fn write_pass_manifest_with_validation_tier(&self, claim_id: &str, validation_tier: &str) {
            let artifact_path = self
                .temp
                .path()
                .join("validation/artifacts/test/claims-gate-review.json");
            fs::write(&artifact_path, r#"{"decision":"pass"}"#).unwrap();
            let digest = content_digest_for_path(&artifact_path).unwrap();
            let manifest = format!(
                r#"{{
  "manifest_version": 2,
  "claim_id": "{claim_id}",
  "evidence_class": "claims-gate-review",
  "validation_tier": "{validation_tier}",
  "scope": "fixture",
  "artifact_path": "validation/artifacts/test/claims-gate-review.json",
  "content_digest": "{digest}",
  "run_id": "fixture-run",
  "source_ref": "{}",
  "outcome": "pass",
  "residual_risk": "fixture residual risk remains bounded",
  "source": "fixture",
  "generated_at": "2026-07-02T00:00:00Z",
  "blocking_issues": []
}}"#,
                self.source_ref
            );
            fs::write(
                self.temp
                    .path()
                    .join("validation/artifacts/test/claims-gate-review.manifest.json"),
                manifest,
            )
            .unwrap();
        }

        fn write_non_claim_inputs(&self) {
            fs::write(
                self.temp.path().join("non-claims.json"),
                r#"{
  "non_claims": [
    "Fixture verdict is not a product release declaration."
  ],
  "residual_risk": [
    "Fixture coverage is not whole-product evidence."
  ]
}"#,
            )
            .unwrap();
        }
    }
}
