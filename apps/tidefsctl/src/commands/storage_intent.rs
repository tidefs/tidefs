// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
//! Storage-intent operator policy and explanation rendering.
//!
//! These surfaces consume supplied storage-intent core records and staged
//! policy-source documents. They deliberately do not scan topology, reopen
//! pool state, activate placement, or infer missing producer evidence.

use std::fs;
use std::path::{Path, PathBuf};
use std::process;

use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use tidefs_storage_intent_core::{
    CostWearRecord, DataShapeRecord, DurabilityState, EvidenceFamilyFreshnessSet,
    EvidenceFamilyFreshnessState, LayoutAllocatorRecord, PrefetchResidencyActionMask,
    PrefetchResidencyCandidateClass, PrefetchResidencyDecisionRecord,
    PrefetchResidencyPolicyEnvelope, PrefetchResidencyPolicyFlags, ReadServingSourceClass,
    ReadSourceFreshnessRecord, RelocationLifecycleRecord, RelocationLifecycleState,
    SkippedMoveReason, StorageIntentDomainId, StorageIntentEvidenceId, StorageIntentEvidenceKind,
    StorageIntentEvidenceQuerySnapshot, StorageIntentEvidenceRef, StorageIntentEvidenceRefs,
    StorageIntentGuaranteeClass, StorageIntentPolicy, StorageIntentPolicyId,
    StorageIntentPolicyRevision, StorageIntentReceipt, StorageIntentReceiptId,
    StorageIntentRefusal, StorageIntentRefusalReason, StorageMediaRole,
};
use tidefs_storage_intent_policy::{
    classify_prefetch_residency_policy_change, compile_prefetch_residency_policy,
    config_to_prefetch_residency_sources, CallerHintSource, CallerRequestFlags,
    DatasetPrefetchResidencyPolicyConfig, InternalMaintenanceIntent,
    PrefetchResidencyPolicyEvidenceState, PrefetchResidencyPolicySource,
    StorageIntentPolicyChangeClass as PolicySourceChangeClass, StorageIntentPolicyCompileResult,
    StorageIntentPolicyCompileStatus, StorageIntentPolicyIdentity,
    StorageIntentPolicyRolloutEvidence, StorageIntentPolicyRolloutRequirements,
};

use crate::parser;

const POLICY_SOURCE_DOCUMENT_VERSION: u16 = 1;

/// Storage-intent operator explanation commands.
#[derive(Subcommand, Debug)]
pub enum StorageIntentCommand {
    /// Explain supplied storage-intent evidence without changing placement
    Explain(StorageIntentExplainArgs),

    /// Stage and preview dataset prefetch/residency policy source documents
    Policy {
        #[command(subcommand)]
        cmd: StorageIntentPolicyCommand,
    },
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

/// `storage-intent policy <set|clear|show|dry-run>`
#[derive(Subcommand, Debug)]
pub enum StorageIntentPolicyCommand {
    /// Build a staged per-dataset prefetch/residency policy source document
    Set(StorageIntentPolicySetArgs),
    /// Build a staged document that clears local prefetch/residency policy fields
    Clear(StorageIntentPolicyClearArgs),
    /// Render a staged prefetch/residency policy source document
    Show(StorageIntentPolicyShowArgs),
    /// Compile and render a staged policy source document without activation
    DryRun(StorageIntentPolicyDryRunArgs),
}

#[derive(Args, Debug)]
pub struct StorageIntentPolicySetArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Action classes this dataset source allows.
    #[arg(long = "allow", value_enum, value_delimiter = ',')]
    pub allow: Vec<PolicyActionArg>,

    /// Action classes this dataset source explicitly refuses.
    #[arg(long = "refuse", value_enum, value_delimiter = ',')]
    pub refuse: Vec<PolicyActionArg>,

    /// Extra evidence or safety flags required by this dataset source.
    #[arg(long = "require", value_enum, value_delimiter = ',')]
    pub require: Vec<PolicyFlagArg>,

    /// Per-dataset cap for prefetch windows, in bytes.
    #[arg(long = "max-prefetch-window-bytes")]
    pub max_prefetch_window_bytes: Option<u64>,

    /// Per-dataset cap for staging capacity, in bytes.
    #[arg(long = "max-staging-bytes")]
    pub max_staging_bytes: Option<u64>,

    /// Minimum sample mass before adaptive feedback can affect this policy.
    #[arg(long = "min-sample-mass")]
    pub min_sample_mass: Option<u32>,

    /// Minimum observation window before adaptive feedback is admissible.
    #[arg(long = "min-observation-window-ms")]
    pub min_observation_window_ms: Option<u64>,

    /// Maximum accepted signal decay age.
    #[arg(long = "max-decay-age-ms")]
    pub max_decay_age_ms: Option<u64>,

    /// Minimum dwell time before movement can be reconsidered.
    #[arg(long = "dwell-min-ms")]
    pub dwell_min_ms: Option<u64>,

    /// Cooldown period after refused, noisy, or failed-payback movement.
    #[arg(long = "cooldown-ms")]
    pub cooldown_ms: Option<u64>,

    /// Name of the policy budget owner shown in staged output.
    #[arg(long = "budget-owner", value_name = "OWNER")]
    pub budget_owner: Option<String>,

    /// Bind a visible resource budget owner as scope=owner.
    #[arg(long = "budget", value_name = "SCOPE=OWNER")]
    pub budgets: Vec<String>,

    /// Allow subject/range override sources for this dataset policy.
    #[arg(long = "admit-subject-range-overrides")]
    pub admit_subject_range_overrides: bool,

    /// Explicit named opt-in for unsafe or volatile action classes.
    #[arg(long = "unsafe-volatile-opt-in")]
    pub unsafe_volatile_opt_in: bool,

    /// Feedback scope allowed to influence future policy candidates.
    #[arg(long = "feedback-mode", value_enum, default_value_t = FeedbackModeArg::Disabled)]
    pub feedback_mode: FeedbackModeArg,

    /// Provenance class for a caller or workload hint in this source preview.
    #[arg(long = "hint-provenance", value_enum, default_value_t = HintProvenanceArg::Absent)]
    pub hint_provenance: HintProvenanceArg,

    /// Caller hint candidate to validate as non-authority policy input.
    #[arg(long = "caller-hint", value_enum)]
    pub caller_hint: Option<PolicyActionArg>,

    /// Treat the preview as if the caller requested sync durability.
    #[arg(long = "caller-sync")]
    pub caller_sync: bool,

    /// Treat the preview as if the caller requested direct I/O.
    #[arg(long = "caller-direct")]
    pub caller_direct: bool,

    /// Treat the preview as if the caller requested FUA.
    #[arg(long = "caller-fua")]
    pub caller_fua: bool,

    /// Treat the preview as if the caller requested a barrier.
    #[arg(long = "caller-barrier")]
    pub caller_barrier: bool,

    /// Treat the preview as if the caller requested stable writes.
    #[arg(long = "caller-stable-write")]
    pub caller_stable_write: bool,

    /// Treat the preview as if the caller bypassed cache.
    #[arg(long = "caller-cache-bypass")]
    pub caller_cache_bypass: bool,

    /// Monotonic source revision to publish in the staged source.
    #[arg(long = "revision", default_value_t = 1)]
    pub revision: u64,

    /// Source generation used for in-flight operation attribution.
    #[arg(long = "generation", default_value_t = 1)]
    pub generation: u64,

    /// Source epoch used for in-flight operation attribution.
    #[arg(long = "epoch", default_value_t = 1)]
    pub epoch: u64,

    /// Write the staged source document JSON to this path.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Emit machine-parseable JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct StorageIntentPolicyClearArgs {
    /// Dataset target in <pool>/<name> form
    pub target: String,

    /// Clear all local prefetch/residency source fields.
    #[arg(long = "all")]
    pub all: bool,

    /// Specific local field groups to clear.
    #[arg(long = "field", value_enum, value_delimiter = ',')]
    pub fields: Vec<PolicyClearFieldArg>,

    /// Monotonic source revision to publish in the staged clear.
    #[arg(long = "revision", default_value_t = 1)]
    pub revision: u64,

    /// Write the staged clear document JSON to this path.
    #[arg(long = "output", short = 'o', value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Emit machine-parseable JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct StorageIntentPolicyShowArgs {
    /// Staged policy source document JSON to render.
    #[arg(long = "input", short = 'i', value_name = "PATH")]
    pub input: PathBuf,

    /// Emit machine-parseable JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct StorageIntentPolicyDryRunArgs {
    /// Staged policy source document JSON to compile and render.
    #[arg(long = "input", short = 'i', value_name = "PATH")]
    pub input: PathBuf,

    /// Existing compiled PrefetchResidencyPolicyEnvelope JSON for rollout classification.
    #[arg(long = "current-envelope", value_name = "PATH")]
    pub current_envelope: Option<PathBuf>,

    /// Emit machine-parseable JSON.
    #[arg(long = "json")]
    pub json: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyActionArg {
    NoPrefetch,
    BoundedReadahead,
    StridedVectorPrefetch,
    MetadataNamespacePrefetch,
    SmallRandomHotsetTrial,
    ManifestIndexPrefetch,
    SnapshotClonePrefetch,
    DegradedReadPrefetch,
    WanGeoDeltaPrefetch,
    ObjectArchiveRestoreStage,
    CacheOnlyTrial,
    VolatileRamTrial,
    IntentBackedRam,
    PmemDurable,
    FlashHotServing,
    HddLocalityOptimized,
    AuthorityPromotionCandidate,
    DemotionCandidate,
    Cooldown,
    NeedMoreEvidence,
    Refused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyFlagArg {
    DatasetScope,
    ServiceObjective,
    EvidenceQuery,
    FreshMediaCapability,
    CostWearEvidence,
    EgressRestoreEvidence,
    PaybackForMovement,
    CapacityReserve,
    TenantIsolation,
    ReadServingBoundary,
    RelocationBoundaryForAuthority,
    ProtectForegroundTail,
    ProtectFlashLifetime,
    TrustDomain,
    TransportBudget,
    SchedulerAdmission,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FeedbackModeArg {
    #[default]
    Disabled,
    ShadowOnly,
    PrefetchWindows,
    CacheOnlyTrials,
    PromotionDemotionCandidates,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum HintProvenanceArg {
    #[default]
    Absent,
    Operator,
    Caller,
    WorkloadDetector,
    LearnedFeedback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyClearFieldArg {
    Actions,
    Limits,
    SignalFloors,
    DwellCooldown,
    UnsafeOptIn,
    Feedback,
    Budgets,
    CallerHints,
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

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PolicySourceDocument {
    version: u16,
    command: String,
    target: String,
    pool: String,
    dataset: String,
    source_state: PolicySourceState,
    revision: u64,
    generation: u64,
    epoch: u64,
    policy_id: String,
    pool_id: String,
    dataset_id: String,
    budget_owner_id: String,
    budget_owner: String,
    allowed_actions: Vec<PolicyActionArg>,
    refused_actions: Vec<PolicyActionArg>,
    required_flags: Vec<PolicyFlagArg>,
    limits: PolicySourceLimits,
    controls: PolicySourceControls,
    budgets: Vec<PolicyBudgetBinding>,
    cleared_fields: Vec<PolicyClearFieldArg>,
    notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PolicySourceState {
    Set,
    Clear,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PolicySourceLimits {
    max_prefetch_window_bytes: Option<u64>,
    max_staging_bytes: Option<u64>,
    min_sample_mass: Option<u32>,
    min_observation_window_ms: Option<u64>,
    max_decay_age_ms: Option<u64>,
    dwell_min_ms: Option<u64>,
    cooldown_ms: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PolicySourceControls {
    admit_subject_range_overrides: bool,
    unsafe_volatile_opt_in: bool,
    feedback_mode: FeedbackModeArg,
    hint_provenance: HintProvenanceArg,
    caller_hint: Option<PolicyActionArg>,
    caller_flags: PolicyCallerFlagsDocument,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct PolicyCallerFlagsDocument {
    sync: bool,
    direct: bool,
    fua: bool,
    barrier: bool,
    stable_write: bool,
    cache_bypass: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
struct PolicyBudgetBinding {
    scope: String,
    owner: String,
}

#[derive(Debug, Serialize)]
struct PolicyDryRunReport {
    command: &'static str,
    target: String,
    source_state: PolicySourceState,
    compile_status: &'static str,
    refusal: String,
    explicit_unsafe_opt_in: bool,
    subject_range_override_admitted: bool,
    envelope: PolicyEnvelopeReport,
    rollout: PolicySupportReport,
    preflight: PolicySupportReport,
    executor_support: Vec<PolicySupportReport>,
    facts: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PolicyEnvelopeReport {
    policy_id: String,
    revision: u64,
    pool_id: String,
    dataset_id: String,
    budget_owner_id: String,
    allowed_actions: Vec<String>,
    flags: Vec<String>,
    max_prefetch_window_bytes: String,
    max_staging_bytes: String,
    min_sample_mass: u32,
    min_observation_window_ms: u64,
    max_decay_age_ms: u64,
    dwell_min_ms: u64,
    cooldown_ms: u64,
}

#[derive(Debug, Serialize)]
struct PolicySupportReport {
    name: String,
    state: &'static str,
    reason: String,
}

pub fn handle_storage_intent(cmd: StorageIntentCommand) {
    match cmd {
        StorageIntentCommand::Explain(args) => handle_explain(args),
        StorageIntentCommand::Policy { cmd } => handle_policy(cmd),
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

fn handle_policy(cmd: StorageIntentPolicyCommand) {
    match cmd {
        StorageIntentPolicyCommand::Set(args) => handle_policy_set(args),
        StorageIntentPolicyCommand::Clear(args) => handle_policy_clear(args),
        StorageIntentPolicyCommand::Show(args) => handle_policy_show(args),
        StorageIntentPolicyCommand::DryRun(args) => handle_policy_dry_run(args),
    }
}

fn handle_policy_set(args: StorageIntentPolicySetArgs) {
    let _guard = crate::commands::authz::require_local_only("storage-intent policy set");
    let document = policy_document_from_set(&args);
    let report = build_policy_dry_run_report(&document, None);
    write_policy_document_if_requested(&document, args.output.as_deref(), "set");

    if args.json {
        print_json_or_exit("tidefsctl storage-intent policy set", &document);
    } else {
        print!("{}", render_policy_source_text(&document, &report));
    }
}

fn handle_policy_clear(args: StorageIntentPolicyClearArgs) {
    let _guard = crate::commands::authz::require_local_only("storage-intent policy clear");
    if !args.all && args.fields.is_empty() {
        eprintln!("tidefsctl storage-intent policy clear: pass --all or at least one --field");
        process::exit(1);
    }

    let document = policy_document_from_clear(&args);
    let report = build_policy_dry_run_report(&document, None);
    write_policy_document_if_requested(&document, args.output.as_deref(), "clear");

    if args.json {
        print_json_or_exit("tidefsctl storage-intent policy clear", &document);
    } else {
        print!("{}", render_policy_source_text(&document, &report));
    }
}

fn handle_policy_show(args: StorageIntentPolicyShowArgs) {
    let document = read_policy_document(&args.input, "show");
    let report = build_policy_dry_run_report(&document, None);
    if args.json {
        print_json_or_exit("tidefsctl storage-intent policy show", &document);
    } else {
        print!("{}", render_policy_source_text(&document, &report));
    }
}

fn handle_policy_dry_run(args: StorageIntentPolicyDryRunArgs) {
    let document = read_policy_document(&args.input, "dry-run");
    let current = args
        .current_envelope
        .as_ref()
        .map(|path| read_current_envelope(path, "dry-run"));
    let report = build_policy_dry_run_report(&document, current.as_ref());

    if args.json {
        print_json_or_exit("tidefsctl storage-intent policy dry-run", &report);
    } else {
        print!("{}", render_policy_dry_run_text(&report));
    }
}

fn policy_document_from_set(args: &StorageIntentPolicySetArgs) -> PolicySourceDocument {
    let target = parse_policy_target(&args.target, "set");
    let budget_owner = args
        .budget_owner
        .clone()
        .unwrap_or_else(|| format!("{}/{}", target.pool, target.dataset));
    let allowed_actions = if args.allow.is_empty() {
        vec![PolicyActionArg::NoPrefetch]
    } else {
        args.allow.clone()
    };
    let budgets = parse_budget_bindings(&args.budgets, "set");

    PolicySourceDocument {
        version: POLICY_SOURCE_DOCUMENT_VERSION,
        command: "storage-intent policy set".to_string(),
        target: args.target.clone(),
        pool: target.pool.clone(),
        dataset: target.dataset.clone(),
        source_state: PolicySourceState::Set,
        revision: args.revision,
        generation: args.generation,
        epoch: args.epoch,
        policy_id: deterministic_id_hex("policy", &[&args.target, &budget_owner]),
        pool_id: deterministic_id_hex("pool", &[&target.pool]),
        dataset_id: deterministic_id_hex("dataset", &[&args.target]),
        budget_owner_id: deterministic_id_hex("budget-owner", &[&budget_owner]),
        budget_owner,
        allowed_actions,
        refused_actions: args.refuse.clone(),
        required_flags: args.require.clone(),
        limits: PolicySourceLimits {
            max_prefetch_window_bytes: args.max_prefetch_window_bytes,
            max_staging_bytes: args.max_staging_bytes,
            min_sample_mass: args.min_sample_mass,
            min_observation_window_ms: args.min_observation_window_ms,
            max_decay_age_ms: args.max_decay_age_ms,
            dwell_min_ms: args.dwell_min_ms,
            cooldown_ms: args.cooldown_ms,
        },
        controls: PolicySourceControls {
            admit_subject_range_overrides: args.admit_subject_range_overrides,
            unsafe_volatile_opt_in: args.unsafe_volatile_opt_in,
            feedback_mode: args.feedback_mode,
            hint_provenance: args.hint_provenance,
            caller_hint: args.caller_hint,
            caller_flags: PolicyCallerFlagsDocument {
                sync: args.caller_sync,
                direct: args.caller_direct,
                fua: args.caller_fua,
                barrier: args.caller_barrier,
                stable_write: args.caller_stable_write,
                cache_bypass: args.caller_cache_bypass,
            },
        },
        budgets,
        cleared_fields: Vec::new(),
        notes: vec![
            "staged source only: no prefetch, promotion, demotion, data movement, budget spend, or runtime authority is activated".to_string(),
            "pool defaults and caller hints cannot relax a stricter dataset source".to_string(),
            "preflight and rollout evidence are rendered unavailable until #926/#901 provide source records".to_string(),
        ],
    }
}

fn policy_document_from_clear(args: &StorageIntentPolicyClearArgs) -> PolicySourceDocument {
    let target = parse_policy_target(&args.target, "clear");
    let budget_owner = format!("{}/{}", target.pool, target.dataset);
    let revision = args.revision.to_string();

    PolicySourceDocument {
        version: POLICY_SOURCE_DOCUMENT_VERSION,
        command: "storage-intent policy clear".to_string(),
        target: args.target.clone(),
        pool: target.pool.clone(),
        dataset: target.dataset.clone(),
        source_state: PolicySourceState::Clear,
        revision: args.revision,
        generation: args.revision,
        epoch: args.revision,
        policy_id: deterministic_id_hex("policy-clear", &[&args.target, &revision]),
        pool_id: deterministic_id_hex("pool", &[&target.pool]),
        dataset_id: deterministic_id_hex("dataset", &[&args.target]),
        budget_owner_id: deterministic_id_hex("budget-owner", &[&budget_owner]),
        budget_owner,
        allowed_actions: Vec::new(),
        refused_actions: Vec::new(),
        required_flags: Vec::new(),
        limits: PolicySourceLimits::default(),
        controls: PolicySourceControls {
            admit_subject_range_overrides: false,
            unsafe_volatile_opt_in: false,
            feedback_mode: FeedbackModeArg::Disabled,
            hint_provenance: HintProvenanceArg::Absent,
            caller_hint: None,
            caller_flags: PolicyCallerFlagsDocument::default(),
        },
        budgets: Vec::new(),
        cleared_fields: if args.all {
            vec![
                PolicyClearFieldArg::Actions,
                PolicyClearFieldArg::Limits,
                PolicyClearFieldArg::SignalFloors,
                PolicyClearFieldArg::DwellCooldown,
                PolicyClearFieldArg::UnsafeOptIn,
                PolicyClearFieldArg::Feedback,
                PolicyClearFieldArg::Budgets,
                PolicyClearFieldArg::CallerHints,
            ]
        } else {
            args.fields.clone()
        },
        notes: vec![
            "clear document removes dataset-local source fields only; inherited and pool defaults remain inheritance inputs".to_string(),
            "clear is staged source only and does not reinterpret old receipts or already-running work".to_string(),
        ],
    }
}

fn parse_policy_target(raw: &str, command: &str) -> parser::DatasetTarget {
    parser::parse_dataset_target(raw).unwrap_or_else(|err| {
        eprintln!("tidefsctl storage-intent policy {command}: {err}");
        process::exit(1);
    })
}

fn parse_budget_bindings(raw: &[String], command: &str) -> Vec<PolicyBudgetBinding> {
    raw.iter()
        .map(|entry| {
            let (scope, owner) = entry.split_once('=').unwrap_or_else(|| {
                eprintln!(
                    "tidefsctl storage-intent policy {command}: budget binding must use scope=owner form"
                );
                process::exit(1);
            });
            let scope = scope.trim();
            let owner = owner.trim();
            if scope.is_empty() || owner.is_empty() {
                eprintln!(
                    "tidefsctl storage-intent policy {command}: budget binding scope and owner must be non-empty"
                );
                process::exit(1);
            }
            PolicyBudgetBinding {
                scope: scope.to_string(),
                owner: owner.to_string(),
            }
        })
        .collect()
}

fn read_policy_document(path: &Path, command: &str) -> PolicySourceDocument {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!(
            "tidefsctl storage-intent policy {command}: failed to read {}: {err}",
            path.display()
        );
        process::exit(1);
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        eprintln!(
            "tidefsctl storage-intent policy {command}: failed to parse {}: {err}",
            path.display()
        );
        process::exit(1);
    })
}

fn read_current_envelope(path: &Path, command: &str) -> PrefetchResidencyPolicyEnvelope {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| {
        eprintln!(
            "tidefsctl storage-intent policy {command}: failed to read current envelope {}: {err}",
            path.display()
        );
        process::exit(1);
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        eprintln!(
            "tidefsctl storage-intent policy {command}: failed to parse current envelope {}: {err}",
            path.display()
        );
        process::exit(1);
    })
}

fn write_policy_document_if_requested(
    document: &PolicySourceDocument,
    output: Option<&Path>,
    command: &str,
) {
    if let Some(path) = output {
        let raw = serde_json::to_string_pretty(document).unwrap_or_else(|err| {
            eprintln!("tidefsctl storage-intent policy {command}: failed to format JSON: {err}");
            process::exit(1);
        });
        fs::write(path, raw).unwrap_or_else(|err| {
            eprintln!(
                "tidefsctl storage-intent policy {command}: failed to write {}: {err}",
                path.display()
            );
            process::exit(1);
        });
    }
}

fn print_json_or_exit<T: Serialize>(command: &str, value: &T) {
    match serde_json::to_string_pretty(value) {
        Ok(raw) => println!("{raw}"),
        Err(err) => {
            eprintln!("{command}: failed to format JSON: {err}");
            process::exit(1);
        }
    }
}

fn build_policy_dry_run_report(
    document: &PolicySourceDocument,
    current: Option<&PrefetchResidencyPolicyEnvelope>,
) -> PolicyDryRunReport {
    let compile = compile_policy_document(document);
    let envelope = envelope_report(&compile.envelope);
    let rollout = rollout_report(current, &compile);
    let preflight = preflight_report(document, &compile);
    let executor_support = executor_support_report(document, &compile);
    let mut facts = vec![
        format!(
            "source-document-version={} source-state={}",
            document.version,
            policy_source_state_label(document.source_state)
        ),
        format!(
            "dataset-target={} pool={} dataset={}",
            document.target, document.pool, document.dataset
        ),
        "compiled through #855 policy-source compiler; this command does not activate runtime authority".to_string(),
        "missing #926 preflight evidence renders activation unavailable, not dry-run proof".to_string(),
        "missing #972 executor support renders action execution blocked or refused, not silently available".to_string(),
    ];

    if document.allowed_actions.is_empty() {
        facts
            .push("allowed-actions: none; local dataset source clears/inherits policy".to_string());
    } else {
        facts.push(format!(
            "requested-allowed-actions: {}",
            policy_action_args_label(&document.allowed_actions)
        ));
    }
    if !document.refused_actions.is_empty() {
        facts.push(format!(
            "requested-refused-actions: {}",
            policy_action_args_label(&document.refused_actions)
        ));
    }
    if !document.required_flags.is_empty() {
        facts.push(format!(
            "requested-required-flags: {}",
            policy_flag_args_label(&document.required_flags)
        ));
    }
    if document.controls.caller_hint.is_some() {
        facts.push(
            "caller/workload hint is treated as prediction input only; it cannot authorize promotion"
                .to_string(),
        );
    }
    for note in &document.notes {
        facts.push(format!("note: {note}"));
    }

    PolicyDryRunReport {
        command: "storage-intent policy dry-run",
        target: document.target.clone(),
        source_state: document.source_state,
        compile_status: compile_status_label(compile.status),
        refusal: compile.refusal.as_str().to_string(),
        explicit_unsafe_opt_in: compile.explicit_unsafe_opt_in,
        subject_range_override_admitted: compile.subject_range_override_admitted,
        envelope,
        rollout,
        preflight,
        executor_support,
        facts,
    }
}

fn compile_policy_document(document: &PolicySourceDocument) -> StorageIntentPolicyCompileResult {
    let identity = StorageIntentPolicyIdentity {
        policy_id: StorageIntentPolicyId(hex16_or_exit(
            &document.policy_id,
            "policy-id",
            "dry-run",
        )),
        policy_revision: StorageIntentPolicyRevision(document.revision),
        pool_id: StorageIntentDomainId(hex16_or_exit(&document.pool_id, "pool-id", "dry-run")),
        dataset_id: StorageIntentDomainId(hex16_or_exit(
            &document.dataset_id,
            "dataset-id",
            "dry-run",
        )),
        budget_owner: StorageIntentDomainId(hex16_or_exit(
            &document.budget_owner_id,
            "budget-owner-id",
            "dry-run",
        )),
    };

    let dataset_source = match document.source_state {
        PolicySourceState::Set => Some(policy_source_from_document(document)),
        PolicySourceState::Clear => None,
    };

    let config = DatasetPrefetchResidencyPolicyConfig {
        dataset: dataset_source,
        admits_subject_range_overrides: Some(document.controls.admit_subject_range_overrides),
        explicit_unsafe_opt_in: Some(document.controls.unsafe_volatile_opt_in),
        default_caller_flags: Some(caller_flags_from_document(&document.controls.caller_flags)),
        default_caller_hints: caller_hint_from_document(document),
        prefetch_window_limit: document.limits.max_prefetch_window_bytes,
        staging_limit: document.limits.max_staging_bytes,
        min_sample_mass: document.limits.min_sample_mass,
        min_observation_window_ms: document.limits.min_observation_window_ms,
        max_decay_age_ms: document.limits.max_decay_age_ms,
        dwell_min_ms: document.limits.dwell_min_ms,
        cooldown_ms: document.limits.cooldown_ms,
        revision: document.revision,
        generation: document.generation,
        epoch: document.epoch,
        ..DatasetPrefetchResidencyPolicyConfig::EMPTY
    };

    let sources = config_to_prefetch_residency_sources(
        &config,
        identity,
        PrefetchResidencyPolicyEvidenceState::default(),
        Default::default(),
        Some(caller_flags_from_document(&document.controls.caller_flags)),
        caller_hint_from_document(document),
        Some(InternalMaintenanceIntent::default()),
        None,
    );

    compile_prefetch_residency_policy(sources)
}

fn policy_source_from_document(document: &PolicySourceDocument) -> PrefetchResidencyPolicySource {
    let allowed_actions = mask_from_action_args(&document.allowed_actions);
    let refused_actions = mask_from_action_args(&document.refused_actions);
    let required_flags = flags_from_args(&document.required_flags);

    let mut source = PrefetchResidencyPolicySource::new(
        tidefs_storage_intent_policy::StorageIntentPolicySourceClass::Dataset,
        allowed_actions,
    )
    .with_source_stamp(
        document.revision,
        document.generation,
        document.epoch,
        StorageIntentEvidenceRef::default(),
    )
    .refusing(refused_actions)
    .requiring(required_flags);

    if let Some(bytes) = document.limits.max_prefetch_window_bytes {
        source = source.with_prefetch_window_limit(bytes);
    }
    if let Some(bytes) = document.limits.max_staging_bytes {
        source = source.with_staging_limit(bytes);
    }
    if document.limits.min_sample_mass.is_some()
        || document.limits.min_observation_window_ms.is_some()
        || document.limits.max_decay_age_ms.is_some()
    {
        source = source.with_signal_floor(
            document.limits.min_sample_mass.unwrap_or_default(),
            document
                .limits
                .min_observation_window_ms
                .unwrap_or_default(),
            document.limits.max_decay_age_ms.unwrap_or_default(),
        );
    }
    if document.limits.dwell_min_ms.is_some() || document.limits.cooldown_ms.is_some() {
        source = source.with_movement_timers(
            document.limits.dwell_min_ms.unwrap_or_default(),
            document.limits.cooldown_ms.unwrap_or_default(),
        );
    }
    if document.controls.admit_subject_range_overrides {
        source = source.admitting_subject_range_overrides();
    }
    if document.controls.unsafe_volatile_opt_in {
        source = source.with_explicit_unsafe_opt_in();
    }

    source
}

fn caller_flags_from_document(flags: &PolicyCallerFlagsDocument) -> CallerRequestFlags {
    CallerRequestFlags {
        sync: flags.sync,
        direct: flags.direct,
        fua: flags.fua,
        barrier: flags.barrier,
        stable_write: flags.stable_write,
        cache_bypass: flags.cache_bypass,
    }
}

fn caller_hint_from_document(document: &PolicySourceDocument) -> Option<CallerHintSource> {
    document.controls.caller_hint.map(|hint| CallerHintSource {
        present: true,
        hotness_hint: true,
        lifetime_hint: matches!(
            document.controls.hint_provenance,
            HintProvenanceArg::Operator | HintProvenanceArg::LearnedFeedback
        ),
        cache_bypass_hint: document.controls.caller_flags.cache_bypass,
        requested_candidate: hint.to_candidate(),
    })
}

fn rollout_report(
    current: Option<&PrefetchResidencyPolicyEnvelope>,
    compile: &StorageIntentPolicyCompileResult,
) -> PolicySupportReport {
    if compile.status == StorageIntentPolicyCompileStatus::Refused {
        return PolicySupportReport {
            name: "#901 rollout".to_string(),
            state: "refused",
            reason: format!(
                "#855 refused the compiled envelope first: {}",
                compile.refusal.as_str()
            ),
        };
    }

    match current {
        Some(current) => {
            let decision = classify_prefetch_residency_policy_change(
                *current,
                compile.envelope,
                StorageIntentPolicyRolloutEvidence::default(),
            );
            let state = if decision.refused { "blocked" } else { "available" };
            PolicySupportReport {
                name: "#901 rollout".to_string(),
                state,
                reason: format!(
                    "change-class={} requirements={} refusal={}; no activation is performed by tidefsctl",
                    policy_change_class_label(decision.change_class),
                    rollout_requirements_label(decision.requirements),
                    decision.refusal.as_str()
                ),
            }
        }
        None => PolicySupportReport {
            name: "#901 rollout".to_string(),
            state: "staged",
            reason:
                "no current envelope supplied; source can be rendered but activation requires rollout evidence and convergence state"
                    .to_string(),
        },
    }
}

fn preflight_report(
    document: &PolicySourceDocument,
    compile: &StorageIntentPolicyCompileResult,
) -> PolicySupportReport {
    if compile.status == StorageIntentPolicyCompileStatus::Refused {
        return PolicySupportReport {
            name: "#926 preflight".to_string(),
            state: "refused",
            reason: format!(
                "compiled policy is refused before preflight: {}",
                compile.refusal.as_str()
            ),
        };
    }

    let requested = mask_from_action_args(&document.allowed_actions);
    if action_mask_requires_preflight(requested) {
        PolicySupportReport {
            name: "#926 preflight".to_string(),
            state: "required-unavailable",
            reason:
                "requested actions may increase memory pressure, flash writes, egress/restore cost, durable movement, or authority; no StorageIntentPreflightSimulationEvidence is supplied"
                    .to_string(),
        }
    } else {
        PolicySupportReport {
            name: "#926 preflight".to_string(),
            state: "not-covered",
            reason:
                "remaining source is low-risk/no-op for this preview; tidefsctl still does not claim dry-run fidelity"
                    .to_string(),
        }
    }
}

fn executor_support_report(
    document: &PolicySourceDocument,
    compile: &StorageIntentPolicyCompileResult,
) -> Vec<PolicySupportReport> {
    let requested = if document.allowed_actions.is_empty() {
        vec![PolicyActionArg::NoPrefetch]
    } else {
        document.allowed_actions.clone()
    };

    requested
        .into_iter()
        .map(|action| {
            let candidate = action.to_candidate();
            let allowed = compile
                .envelope
                .allowed_actions
                .contains_candidate(candidate);
            let (state, reason) = if !allowed {
                (
                    "refused",
                    format!(
                        "#855 lowered or refused this action before execution: {}",
                        compile.refusal.as_str()
                    ),
                )
            } else if matches!(
                candidate,
                PrefetchResidencyCandidateClass::NoPrefetch
                    | PrefetchResidencyCandidateClass::Cooldown
                    | PrefetchResidencyCandidateClass::NeedMoreEvidence
                    | PrefetchResidencyCandidateClass::Refused
            ) {
                (
                    "available",
                    "no #972 runtime executor is required for this non-action/refusal class"
                        .to_string(),
                )
            } else {
                (
                    "blocked",
                    "#972 executor support is not present on master; configuration is source-only"
                        .to_string(),
                )
            };

            PolicySupportReport {
                name: format!("#972 executor {}", candidate.as_str()),
                state,
                reason,
            }
        })
        .collect()
}

fn envelope_report(envelope: &PrefetchResidencyPolicyEnvelope) -> PolicyEnvelopeReport {
    PolicyEnvelopeReport {
        policy_id: domain_id(&envelope.policy_id.0),
        revision: envelope.policy_revision.0,
        pool_id: domain_id(&envelope.pool_id.0),
        dataset_id: domain_id(&envelope.dataset_id.0),
        budget_owner_id: domain_id(&envelope.budget_owner.0),
        allowed_actions: action_mask_labels(envelope.allowed_actions),
        flags: policy_flag_labels(envelope.flags),
        max_prefetch_window_bytes: policy_limit_label(envelope.max_prefetch_window_bytes),
        max_staging_bytes: policy_limit_label(envelope.max_staging_bytes),
        min_sample_mass: envelope.min_sample_mass,
        min_observation_window_ms: envelope.min_observation_window_ms,
        max_decay_age_ms: envelope.max_decay_age_ms,
        dwell_min_ms: envelope.dwell_min_ms,
        cooldown_ms: envelope.cooldown_ms,
    }
}

fn render_policy_source_text(
    document: &PolicySourceDocument,
    report: &PolicyDryRunReport,
) -> String {
    let mut out = String::new();
    out.push_str("storage-intent policy source\n");
    out.push_str(&format!("  command: {}\n", document.command));
    out.push_str(&format!("  target: {}\n", document.target));
    out.push_str(&format!(
        "  source-state: {}\n",
        policy_source_state_label(document.source_state)
    ));
    out.push_str(&format!("  budget-owner: {}\n", document.budget_owner));
    out.push_str(&format!(
        "  allowed-actions: {}\n",
        policy_action_args_label(&document.allowed_actions)
    ));
    out.push_str(&format!(
        "  refused-actions: {}\n",
        policy_action_args_label(&document.refused_actions)
    ));
    out.push_str(&format!(
        "  required-flags: {}\n",
        policy_flag_args_label(&document.required_flags)
    ));
    out.push_str(&format!(
        "  compile: status={} refusal={}\n",
        report.compile_status, report.refusal
    ));
    out.push_str(
        "  validation: compiled through #855 policy-source compiler; staged source is not authority\n",
    );
    out.push_str(&format!(
        "  rollout: {} ({})\n",
        report.rollout.state, report.rollout.reason
    ));
    out.push_str(&format!(
        "  preflight: {} ({})\n",
        report.preflight.state, report.preflight.reason
    ));
    out.push_str("  executor-support:\n");
    for support in &report.executor_support {
        out.push_str(&format!(
            "    - {}: {} ({})\n",
            support.name, support.state, support.reason
        ));
    }
    out.push_str("  non-authority: no runtime action, budget spend, receipt reinterpretation, or source retirement is performed\n");
    out
}

fn render_policy_dry_run_text(report: &PolicyDryRunReport) -> String {
    let mut out = String::new();
    out.push_str("storage-intent policy dry-run\n");
    out.push_str(&format!("  target: {}\n", report.target));
    out.push_str(&format!(
        "  source-state: {}\n",
        policy_source_state_label(report.source_state)
    ));
    out.push_str(&format!(
        "  compile: status={} refusal={}\n",
        report.compile_status, report.refusal
    ));
    out.push_str("  compiled-envelope:\n");
    out.push_str(&format!("    policy-id: {}\n", report.envelope.policy_id));
    out.push_str(&format!("    revision: {}\n", report.envelope.revision));
    out.push_str(&format!(
        "    budget-owner-id: {}\n",
        report.envelope.budget_owner_id
    ));
    out.push_str(&format!(
        "    allowed-actions: {}\n",
        comma_or_none(report.envelope.allowed_actions.iter().map(String::as_str))
    ));
    out.push_str(&format!(
        "    flags: {}\n",
        comma_or_none(report.envelope.flags.iter().map(String::as_str))
    ));
    out.push_str(&format!(
        "    caps: prefetch={} staging={}\n",
        report.envelope.max_prefetch_window_bytes, report.envelope.max_staging_bytes
    ));
    out.push_str(&format!(
        "    signal-floors: sample-mass={} observation={}ms decay={}ms\n",
        report.envelope.min_sample_mass,
        report.envelope.min_observation_window_ms,
        report.envelope.max_decay_age_ms
    ));
    out.push_str(&format!(
        "    dwell-cooldown: dwell={}ms cooldown={}ms\n",
        report.envelope.dwell_min_ms, report.envelope.cooldown_ms
    ));
    out.push_str(&format!(
        "  rollout: {} ({})\n",
        report.rollout.state, report.rollout.reason
    ));
    out.push_str(&format!(
        "  preflight: {} ({})\n",
        report.preflight.state, report.preflight.reason
    ));
    out.push_str("  executor-support:\n");
    for support in &report.executor_support {
        out.push_str(&format!(
            "    - {}: {} ({})\n",
            support.name, support.state, support.reason
        ));
    }
    out.push_str("  facts:\n");
    for fact in &report.facts {
        out.push_str(&format!("    - {fact}\n"));
    }
    out
}

fn mask_from_action_args(actions: &[PolicyActionArg]) -> PrefetchResidencyActionMask {
    actions
        .iter()
        .fold(PrefetchResidencyActionMask::EMPTY, |mask, action| {
            mask.with(action.to_candidate())
        })
}

fn flags_from_args(flags: &[PolicyFlagArg]) -> PrefetchResidencyPolicyFlags {
    flags
        .iter()
        .fold(PrefetchResidencyPolicyFlags::EMPTY, |mask, flag| {
            mask.union(flag.to_flag())
        })
}

fn action_mask_labels(mask: PrefetchResidencyActionMask) -> Vec<String> {
    POLICY_ACTIONS
        .iter()
        .map(|action| action.to_candidate())
        .filter(|candidate| mask.contains_candidate(*candidate))
        .map(|candidate| candidate.as_str().to_string())
        .collect()
}

fn policy_flag_labels(flags: PrefetchResidencyPolicyFlags) -> Vec<String> {
    POLICY_FLAGS
        .iter()
        .copied()
        .filter(|flag| flags.contains_all(flag.to_flag()))
        .map(|flag| flag.label().to_string())
        .collect()
}

fn action_mask_requires_preflight(mask: PrefetchResidencyActionMask) -> bool {
    [
        PrefetchResidencyCandidateClass::SmallRandomHotsetTrial,
        PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
        PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage,
        PrefetchResidencyCandidateClass::VolatileRamTrial,
        PrefetchResidencyCandidateClass::IntentBackedRam,
        PrefetchResidencyCandidateClass::PmemDurable,
        PrefetchResidencyCandidateClass::FlashHotServing,
        PrefetchResidencyCandidateClass::HddLocalityOptimized,
        PrefetchResidencyCandidateClass::AuthorityPromotionCandidate,
        PrefetchResidencyCandidateClass::DemotionCandidate,
    ]
    .iter()
    .any(|candidate| mask.contains_candidate(*candidate))
}

fn compile_status_label(status: StorageIntentPolicyCompileStatus) -> &'static str {
    match status {
        StorageIntentPolicyCompileStatus::Refused => "refused",
        StorageIntentPolicyCompileStatus::Compiled => "compiled",
        StorageIntentPolicyCompileStatus::Lowered => "lowered",
        StorageIntentPolicyCompileStatus::UnsafeVisible => "unsafe-visible",
        StorageIntentPolicyCompileStatus::DegradedVisible => "degraded-visible",
    }
}

fn policy_change_class_label(class: PolicySourceChangeClass) -> &'static str {
    match class {
        PolicySourceChangeClass::Unchanged => "unchanged",
        PolicySourceChangeClass::EquivalentRevision => "equivalent-revision",
        PolicySourceChangeClass::Tightening => "tightening",
        PolicySourceChangeClass::Relaxing => "relaxing",
        PolicySourceChangeClass::ConvergenceRequired => "convergence-required",
        PolicySourceChangeClass::UnsafeDowngrade => "unsafe-downgrade",
        PolicySourceChangeClass::BudgetOwnerChange => "budget-owner-change",
        PolicySourceChangeClass::Incompatible => "incompatible",
    }
}

fn rollout_requirements_label(requirements: StorageIntentPolicyRolloutRequirements) -> String {
    comma_or_none(
        [
            (
                StorageIntentPolicyRolloutRequirements::OPERATOR_CONSENT,
                "operator-consent",
            ),
            (
                StorageIntentPolicyRolloutRequirements::NEW_WRITES_ONLY,
                "new-writes-only",
            ),
            (
                StorageIntentPolicyRolloutRequirements::RECEIPT_VISIBLE_DEGRADATION,
                "receipt-visible-degradation",
            ),
            (
                StorageIntentPolicyRolloutRequirements::CONVERGENCE_REQUIRED,
                "convergence-required",
            ),
            (
                StorageIntentPolicyRolloutRequirements::ROLLOUT_EVIDENCE,
                "rollout-evidence",
            ),
        ]
        .into_iter()
        .filter_map(|(flag, label)| requirements.contains_all(flag).then_some(label)),
    )
}

fn policy_source_state_label(state: PolicySourceState) -> &'static str {
    match state {
        PolicySourceState::Set => "set",
        PolicySourceState::Clear => "clear",
    }
}

fn policy_action_args_label(actions: &[PolicyActionArg]) -> String {
    comma_or_none(actions.iter().map(|action| action.to_candidate().as_str()))
}

fn policy_flag_args_label(flags: &[PolicyFlagArg]) -> String {
    comma_or_none(flags.iter().map(|flag| flag.label()))
}

fn comma_or_none<'a>(values: impl IntoIterator<Item = &'a str>) -> String {
    let mut values = values.into_iter();
    let Some(first) = values.next() else {
        return "none".to_string();
    };

    let mut out = first.to_string();
    for value in values {
        out.push(',');
        out.push_str(value);
    }
    out
}

fn policy_limit_label(value: u64) -> String {
    if value == u64::MAX {
        "unbounded".to_string()
    } else {
        value.to_string()
    }
}

fn deterministic_id_hex(kind: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    update_hash_field(&mut hasher, "tidefsctl-storage-intent-policy-source-v1");
    update_hash_field(&mut hasher, kind);
    for part in parts {
        update_hash_field(&mut hasher, part);
    }
    let digest = hasher.finalize();
    let mut id = [0_u8; 16];
    id.copy_from_slice(&digest.as_bytes()[..16]);
    if id.iter().all(|byte| *byte == 0) {
        id[15] = 1;
    }
    hex_encode(&id)
}

fn update_hash_field(hasher: &mut blake3::Hasher, value: &str) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

fn hex16_or_exit(raw: &str, field: &str, command: &str) -> [u8; 16] {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 32 {
        eprintln!(
            "tidefsctl storage-intent policy {command}: {field} must be a 16-byte hex string"
        );
        process::exit(1);
    }
    let mut out = [0_u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let part = std::str::from_utf8(chunk).unwrap_or_else(|err| {
            eprintln!("tidefsctl storage-intent policy {command}: {field} is not UTF-8 hex: {err}");
            process::exit(1);
        });
        out[index] = u8::from_str_radix(part, 16).unwrap_or_else(|err| {
            eprintln!(
                "tidefsctl storage-intent policy {command}: invalid {field} byte {part}: {err}"
            );
            process::exit(1);
        });
    }
    if out.iter().all(|byte| *byte == 0) {
        eprintln!("tidefsctl storage-intent policy {command}: {field} must not be zero");
        process::exit(1);
    }
    out
}

const POLICY_ACTIONS: [PolicyActionArg; 21] = [
    PolicyActionArg::NoPrefetch,
    PolicyActionArg::BoundedReadahead,
    PolicyActionArg::StridedVectorPrefetch,
    PolicyActionArg::MetadataNamespacePrefetch,
    PolicyActionArg::SmallRandomHotsetTrial,
    PolicyActionArg::ManifestIndexPrefetch,
    PolicyActionArg::SnapshotClonePrefetch,
    PolicyActionArg::DegradedReadPrefetch,
    PolicyActionArg::WanGeoDeltaPrefetch,
    PolicyActionArg::ObjectArchiveRestoreStage,
    PolicyActionArg::CacheOnlyTrial,
    PolicyActionArg::VolatileRamTrial,
    PolicyActionArg::IntentBackedRam,
    PolicyActionArg::PmemDurable,
    PolicyActionArg::FlashHotServing,
    PolicyActionArg::HddLocalityOptimized,
    PolicyActionArg::AuthorityPromotionCandidate,
    PolicyActionArg::DemotionCandidate,
    PolicyActionArg::Cooldown,
    PolicyActionArg::NeedMoreEvidence,
    PolicyActionArg::Refused,
];

const POLICY_FLAGS: [PolicyFlagArg; 16] = [
    PolicyFlagArg::DatasetScope,
    PolicyFlagArg::ServiceObjective,
    PolicyFlagArg::EvidenceQuery,
    PolicyFlagArg::FreshMediaCapability,
    PolicyFlagArg::CostWearEvidence,
    PolicyFlagArg::EgressRestoreEvidence,
    PolicyFlagArg::PaybackForMovement,
    PolicyFlagArg::CapacityReserve,
    PolicyFlagArg::TenantIsolation,
    PolicyFlagArg::ReadServingBoundary,
    PolicyFlagArg::RelocationBoundaryForAuthority,
    PolicyFlagArg::ProtectForegroundTail,
    PolicyFlagArg::ProtectFlashLifetime,
    PolicyFlagArg::TrustDomain,
    PolicyFlagArg::TransportBudget,
    PolicyFlagArg::SchedulerAdmission,
];

impl PolicyActionArg {
    fn to_candidate(self) -> PrefetchResidencyCandidateClass {
        match self {
            Self::NoPrefetch => PrefetchResidencyCandidateClass::NoPrefetch,
            Self::BoundedReadahead => PrefetchResidencyCandidateClass::BoundedReadahead,
            Self::StridedVectorPrefetch => PrefetchResidencyCandidateClass::StridedVectorPrefetch,
            Self::MetadataNamespacePrefetch => {
                PrefetchResidencyCandidateClass::MetadataNamespacePrefetch
            }
            Self::SmallRandomHotsetTrial => PrefetchResidencyCandidateClass::SmallRandomHotsetTrial,
            Self::ManifestIndexPrefetch => PrefetchResidencyCandidateClass::ManifestIndexPrefetch,
            Self::SnapshotClonePrefetch => PrefetchResidencyCandidateClass::SnapshotClonePrefetch,
            Self::DegradedReadPrefetch => PrefetchResidencyCandidateClass::DegradedReadPrefetch,
            Self::WanGeoDeltaPrefetch => PrefetchResidencyCandidateClass::WanGeoDeltaPrefetch,
            Self::ObjectArchiveRestoreStage => {
                PrefetchResidencyCandidateClass::ObjectArchiveRestoreStage
            }
            Self::CacheOnlyTrial => PrefetchResidencyCandidateClass::CacheOnlyTrial,
            Self::VolatileRamTrial => PrefetchResidencyCandidateClass::VolatileRamTrial,
            Self::IntentBackedRam => PrefetchResidencyCandidateClass::IntentBackedRam,
            Self::PmemDurable => PrefetchResidencyCandidateClass::PmemDurable,
            Self::FlashHotServing => PrefetchResidencyCandidateClass::FlashHotServing,
            Self::HddLocalityOptimized => PrefetchResidencyCandidateClass::HddLocalityOptimized,
            Self::AuthorityPromotionCandidate => {
                PrefetchResidencyCandidateClass::AuthorityPromotionCandidate
            }
            Self::DemotionCandidate => PrefetchResidencyCandidateClass::DemotionCandidate,
            Self::Cooldown => PrefetchResidencyCandidateClass::Cooldown,
            Self::NeedMoreEvidence => PrefetchResidencyCandidateClass::NeedMoreEvidence,
            Self::Refused => PrefetchResidencyCandidateClass::Refused,
        }
    }
}

impl PolicyFlagArg {
    fn to_flag(self) -> PrefetchResidencyPolicyFlags {
        match self {
            Self::DatasetScope => PrefetchResidencyPolicyFlags::REQUIRE_DATASET_SCOPE,
            Self::ServiceObjective => PrefetchResidencyPolicyFlags::REQUIRE_SERVICE_OBJECTIVE,
            Self::EvidenceQuery => PrefetchResidencyPolicyFlags::REQUIRE_EVIDENCE_QUERY,
            Self::FreshMediaCapability => {
                PrefetchResidencyPolicyFlags::REQUIRE_FRESH_MEDIA_CAPABILITY
            }
            Self::CostWearEvidence => PrefetchResidencyPolicyFlags::REQUIRE_COST_WEAR_EVIDENCE,
            Self::EgressRestoreEvidence => {
                PrefetchResidencyPolicyFlags::REQUIRE_EGRESS_RESTORE_EVIDENCE
            }
            Self::PaybackForMovement => PrefetchResidencyPolicyFlags::REQUIRE_PAYBACK_FOR_MOVEMENT,
            Self::CapacityReserve => PrefetchResidencyPolicyFlags::REQUIRE_CAPACITY_RESERVE,
            Self::TenantIsolation => PrefetchResidencyPolicyFlags::REQUIRE_TENANT_ISOLATION,
            Self::ReadServingBoundary => {
                PrefetchResidencyPolicyFlags::REQUIRE_READ_SERVING_BOUNDARY
            }
            Self::RelocationBoundaryForAuthority => {
                PrefetchResidencyPolicyFlags::REQUIRE_RELOCATION_BOUNDARY_FOR_AUTHORITY
            }
            Self::ProtectForegroundTail => PrefetchResidencyPolicyFlags::PROTECT_FOREGROUND_TAIL,
            Self::ProtectFlashLifetime => PrefetchResidencyPolicyFlags::PROTECT_FLASH_LIFETIME,
            Self::TrustDomain => PrefetchResidencyPolicyFlags::REQUIRE_TRUST_DOMAIN,
            Self::TransportBudget => PrefetchResidencyPolicyFlags::REQUIRE_TRANSPORT_BUDGET,
            Self::SchedulerAdmission => PrefetchResidencyPolicyFlags::REQUIRE_SCHEDULER_ADMISSION,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::DatasetScope => "dataset-scope",
            Self::ServiceObjective => "service-objective",
            Self::EvidenceQuery => "evidence-query",
            Self::FreshMediaCapability => "fresh-media-capability",
            Self::CostWearEvidence => "cost-wear-evidence",
            Self::EgressRestoreEvidence => "egress-restore-evidence",
            Self::PaybackForMovement => "payback-for-movement",
            Self::CapacityReserve => "capacity-reserve",
            Self::TenantIsolation => "tenant-isolation",
            Self::ReadServingBoundary => "read-serving-boundary",
            Self::RelocationBoundaryForAuthority => "relocation-boundary-for-authority",
            Self::ProtectForegroundTail => "protect-foreground-tail",
            Self::ProtectFlashLifetime => "protect-flash-lifetime",
            Self::TrustDomain => "trust-domain",
            Self::TransportBudget => "transport-budget",
            Self::SchedulerAdmission => "scheduler-admission",
        }
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
                "allocation={} region={} fragmentation={}ppm locality={}ppm free-run-pressure={}ppm grain={} extent-alignment={} stripe-alignment={} block-volume-alignment={} optimal-io={} zone-write-pointer={} pending-free={} pending-free-safety={} reclaim-debt={} stale-pointer-refusal={} evidence={}",
                layout.allocation_class.as_str(),
                layout.region_class.as_str(),
                layout.fragmentation_ppm,
                layout.locality_score_ppm,
                layout.free_run_pressure_ppm,
                layout.grain_bytes,
                layout.extent_alignment_bytes,
                layout.stripe_alignment_bytes,
                layout.block_volume_alignment_bytes,
                layout.device_optimal_io_bytes,
                layout.zone_write_pointer,
                layout.pending_free_bytes,
                layout.pending_free_safety.as_str(),
                layout.reclaim_debt_bytes,
                layout.stale_pointer_refusal,
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

    fn policy_set_args(allow: Vec<PolicyActionArg>) -> StorageIntentPolicySetArgs {
        StorageIntentPolicySetArgs {
            target: "tank/fs".to_string(),
            allow,
            refuse: Vec::new(),
            require: Vec::new(),
            max_prefetch_window_bytes: Some(1 << 20),
            max_staging_bytes: Some(1 << 30),
            min_sample_mass: Some(64),
            min_observation_window_ms: Some(30_000),
            max_decay_age_ms: Some(300_000),
            dwell_min_ms: Some(60_000),
            cooldown_ms: Some(120_000),
            budget_owner: Some("dataset-a".to_string()),
            budgets: vec![
                "ram=dataset-a".to_string(),
                "flash-wear=dataset-a".to_string(),
            ],
            admit_subject_range_overrides: false,
            unsafe_volatile_opt_in: false,
            feedback_mode: FeedbackModeArg::PrefetchWindows,
            hint_provenance: HintProvenanceArg::Operator,
            caller_hint: None,
            caller_sync: false,
            caller_direct: false,
            caller_fua: false,
            caller_barrier: false,
            caller_stable_write: false,
            caller_cache_bypass: false,
            revision: 1,
            generation: 1,
            epoch: 1,
            output: None,
            json: false,
        }
    }

    #[test]
    fn policy_set_document_renders_staged_non_authority() {
        let args = policy_set_args(vec![
            PolicyActionArg::BoundedReadahead,
            PolicyActionArg::CacheOnlyTrial,
        ]);
        let document = policy_document_from_set(&args);
        let report = build_policy_dry_run_report(&document, None);
        let text = render_policy_source_text(&document, &report);

        assert!(text.contains("storage-intent policy source"));
        assert!(text.contains("target: tank/fs"));
        assert!(text.contains("budget-owner: dataset-a"));
        assert!(text.contains("compiled through #855"));
        assert!(text.contains("no runtime action"));
    }

    #[test]
    fn volatile_ram_trial_requires_explicit_opt_in() {
        let args = policy_set_args(vec![PolicyActionArg::VolatileRamTrial]);
        let document = policy_document_from_set(&args);
        let report = build_policy_dry_run_report(&document, None);

        assert!(matches!(report.compile_status, "lowered" | "refused"));
        assert_ne!(report.refusal, "none");
        assert!(
            !report
                .envelope
                .allowed_actions
                .iter()
                .any(|action| action == "volatile-ram-trial"),
            "volatile RAM must not be admitted without explicit opt-in"
        );
    }

    #[test]
    fn hotness_hint_alone_does_not_authorize_promotion() {
        let mut args = policy_set_args(vec![PolicyActionArg::AuthorityPromotionCandidate]);
        args.caller_hint = Some(PolicyActionArg::AuthorityPromotionCandidate);
        args.hint_provenance = HintProvenanceArg::Caller;
        let document = policy_document_from_set(&args);
        let report = build_policy_dry_run_report(&document, None);

        assert!(
            !report
                .envelope
                .allowed_actions
                .iter()
                .any(|action| action == "authority-promotion-candidate"),
            "caller hotness hints must not authorize promotion"
        );
        assert!(report
            .facts
            .iter()
            .any(|fact| fact.contains("cannot authorize promotion")));
    }

    #[test]
    fn costly_flash_policy_without_evidence_renders_blocked_support() {
        let mut args = policy_set_args(vec![PolicyActionArg::FlashHotServing]);
        args.require = vec![
            PolicyFlagArg::FreshMediaCapability,
            PolicyFlagArg::CostWearEvidence,
            PolicyFlagArg::CapacityReserve,
        ];
        let document = policy_document_from_set(&args);
        let report = build_policy_dry_run_report(&document, None);

        assert_eq!(report.preflight.state, "required-unavailable");
        assert!(matches!(report.compile_status, "lowered" | "refused"));
        assert!(report
            .executor_support
            .iter()
            .any(|support| support.state == "refused" || support.state == "blocked"));
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
