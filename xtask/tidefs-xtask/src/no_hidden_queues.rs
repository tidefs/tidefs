// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const REGISTRY_PATH: &str = "validation/performance/no-hidden-queues.toml";
const CLAIMS_PATH: &str = "validation/claims.toml";
const RECEIPT_DIR: &str = "validation/artifacts/performance";
const RECEIPT_FILE_PREFIX: &str = "no-hidden-queues-";
const RECEIPT_FILE_SUFFIX: &str = ".toml";
const REVIEW_RECEIPT_VERSION: u32 = 1;
const REVIEW_RECEIPT_EVIDENCE_CLASS: &str = "no-hidden-queues-review-receipt";
const REVIEW_RECEIPT_EVIDENCE_TIER: &str = "source-registry-review";
const REVIEW_RECEIPT_SOURCE_COVERAGE_KIND: &str = "recursive-source-registry-review";
const REVIEW_RECEIPT_RUNTIME_BOUNDARY: &str =
    "source-registry-review-only-does-not-satisfy-queue-depth-runtime-artifact";
const REVIEW_RECEIPT_DECISION: &str = "claims-remain-blocked";
const QUEUE_ROOT_COVERAGE_KIND: &str = "registered-source-semantics-present";
const QUEUE_DEPTH_RUNTIME_ARTIFACT: &str = "queue-depth-runtime-artifact";
const SCHEDULER_DIRTY_DEBT_CLAIM: &str = "scheduler.dirty_debt.no_hidden.v1";
const SCHEDULER_DIRTY_DEBT_RUNTIME_ARTIFACT_PATH: &str =
    "validation/artifacts/performance/queue-depth-runtime.json";
const SCHEDULER_DIRTY_DEBT_RUNTIME_MANIFEST_PATH: &str =
    "validation/artifacts/performance/scheduler-dirty-debt-queue-depth-runtime.manifest.json";
const REQUIRED_RUNTIME_SCOPE_FIELDS: &[&str] =
    &["workload", "topology", "scope", "refusal_boundaries"];

const VALID_WORK_CLASSES: &[&str] = &[
    "foreground-read",
    "foreground-write",
    "metadata-mutation",
    "writeback-flush",
    "scrub",
    "reclaim",
    "compaction",
    "control-plane",
];

const VALID_RESOURCE_DOMAINS: &[&str] = &[
    "foreground-io",
    "background-io",
    "dirty-bytes",
    "dirty-operations",
    "dirty-age",
    "metadata",
    "queue-slots",
    "cpu",
];

const VALID_HARD_CAPS: &[&str] = &[
    "dirty-bytes",
    "dirty-operations",
    "dirty-age",
    "queue-slots",
];

#[derive(Debug)]
pub struct NoHiddenQueuesError {
    failures: Vec<String>,
}

impl fmt::Display for NoHiddenQueuesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "no-hidden-queues check failed:")?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
struct QueueRegistry {
    schema_version: u32,
    scheduler_wide_runtime_evidence: SchedulerWideRuntimeEvidence,
    queue_roots: Vec<QueueRoot>,
}

#[derive(Debug, Deserialize)]
struct SchedulerWideRuntimeEvidence {
    claim_id: String,
    required_evidence_class: String,
    artifact_path: String,
    manifest_path: String,
    source_registry_boundary: String,
    required_scope_fields: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct QueueRoot {
    id: String,
    package: String,
    path: String,
    symbol: String,
    work_class: String,
    resource_domains: Vec<String>,
    admission: String,
    service_curve: String,
    hard_caps: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ClaimRegistry {
    claims: Vec<RegisteredClaim>,
}

#[derive(Debug, Deserialize)]
struct RegisteredClaim {
    id: String,
    status: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoHiddenQueuesReviewReceipt {
    receipt_version: u32,
    evidence_class: String,
    evidence_tier: String,
    issue: u32,
    registry_path: String,
    registry_schema_version: u32,
    source_coverage_kind: String,
    runtime_artifact_boundary: String,
    decision: String,
    reviewed_at: String,
    reviewer: ReceiptReviewer,
    tool: ReceiptTool,
    scanned_roots: Vec<ReceiptScannedRoot>,
    queue_root_coverage: Vec<ReceiptQueueRootCoverage>,
    out_of_scope: Vec<ReceiptOutOfScope>,
    affected_claim_ids: Vec<String>,
    blocked_claim_ids: Vec<String>,
    non_claims: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptReviewer {
    name: String,
    role: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptTool {
    name: String,
    command: String,
    version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptScannedRoot {
    name: String,
    package: String,
    path: String,
    scan: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptQueueRootCoverage {
    id: String,
    package: String,
    path: String,
    symbol: String,
    source_root: String,
    coverage: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptOutOfScope {
    root: String,
    reason: String,
    owner_issue: u32,
    claim_ids: Vec<String>,
    does_not_satisfy_evidence_classes: Vec<String>,
}

pub fn check_current_workspace() -> Result<(), NoHiddenQueuesError> {
    let root = find_workspace_root().ok_or_else(|| NoHiddenQueuesError {
        failures: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut failures = Vec::new();
    let registry = load_registry(&root, &mut failures);
    let touched_files = touched_implementation_files(&root, &mut failures);
    let (scanned_files, touched_package_count) =
        scanned_source_files_for_touched_packages(&root, &touched_files, &mut failures);

    if let Some(registry) = registry {
        validate_registry(&root, &registry, &mut failures);
        scan_source_files(&root, &registry, &scanned_files, &mut failures);
        validate_workspace_review_receipts(&root, &registry, &mut failures);

        if failures.is_empty() {
            println!(
                "no-hidden-queues ok: {} registered queue root(s), {} touched implementation package(s), {} source file(s) scanned",
                registry.queue_roots.len(),
                touched_package_count,
                scanned_files.len()
            );
            return Ok(());
        }
    }

    Err(NoHiddenQueuesError { failures })
}

pub fn validate_review_receipt_current_workspace(
    receipt_path: &str,
) -> Result<(), NoHiddenQueuesError> {
    let root = find_workspace_root().ok_or_else(|| NoHiddenQueuesError {
        failures: vec!["could not locate workspace root Cargo.toml".to_string()],
    })?;
    let mut failures = Vec::new();
    let registry = load_registry(&root, &mut failures);
    let claims = load_claim_registry(&root, &mut failures);
    let receipt_rel = workspace_relative_arg(receipt_path, "receipt path", &mut failures);

    if let (Some(registry), Some(claims), Some(receipt_rel)) = (&registry, &claims, &receipt_rel) {
        validate_registry(&root, registry, &mut failures);
        if let Some(receipt) = load_review_receipt(&root, receipt_rel, &mut failures) {
            validate_review_receipt(
                &root,
                receipt_rel,
                &receipt,
                registry,
                claims,
                &mut failures,
            );
        }
    }

    if failures.is_empty() {
        println!(
            "no-hidden-queues receipt ok: {}",
            receipt_path.replace('\\', "/")
        );
        Ok(())
    } else {
        Err(NoHiddenQueuesError { failures })
    }
}

fn load_registry(root: &Path, failures: &mut Vec<String>) -> Option<QueueRegistry> {
    let path = root.join(REGISTRY_PATH);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!("could not read `{REGISTRY_PATH}`: {err}"));
            return None;
        }
    };
    match toml::from_str::<QueueRegistry>(&text) {
        Ok(registry) => Some(registry),
        Err(err) => {
            failures.push(format!("could not parse `{REGISTRY_PATH}`: {err}"));
            None
        }
    }
}

fn load_claim_registry(root: &Path, failures: &mut Vec<String>) -> Option<ClaimRegistry> {
    let path = root.join(CLAIMS_PATH);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!("could not read `{CLAIMS_PATH}`: {err}"));
            return None;
        }
    };
    match toml::from_str::<ClaimRegistry>(&text) {
        Ok(registry) => Some(registry),
        Err(err) => {
            failures.push(format!("could not parse `{CLAIMS_PATH}`: {err}"));
            None
        }
    }
}

fn validate_registry(root: &Path, registry: &QueueRegistry, failures: &mut Vec<String>) {
    if registry.schema_version != 1 {
        failures.push(format!(
            "`{REGISTRY_PATH}` schema_version must be 1, found {}",
            registry.schema_version
        ));
    }
    if registry.queue_roots.is_empty() {
        failures.push(format!(
            "`{REGISTRY_PATH}` must register at least one queue root"
        ));
    }
    validate_scheduler_wide_runtime_evidence(&registry.scheduler_wide_runtime_evidence, failures);

    let mut ids = BTreeSet::new();
    for queue in &registry.queue_roots {
        if !ids.insert(queue.id.as_str()) {
            failures.push(format!("duplicate queue root id `{}`", queue.id));
        }
        validate_queue_root(root, queue, failures);
    }
}

fn validate_scheduler_wide_runtime_evidence(
    evidence: &SchedulerWideRuntimeEvidence,
    failures: &mut Vec<String>,
) {
    validate_exact_registry_field(
        "scheduler_wide_runtime_evidence.claim_id",
        &evidence.claim_id,
        SCHEDULER_DIRTY_DEBT_CLAIM,
        failures,
    );
    validate_exact_registry_field(
        "scheduler_wide_runtime_evidence.required_evidence_class",
        &evidence.required_evidence_class,
        QUEUE_DEPTH_RUNTIME_ARTIFACT,
        failures,
    );
    validate_exact_registry_field(
        "scheduler_wide_runtime_evidence.artifact_path",
        &evidence.artifact_path,
        SCHEDULER_DIRTY_DEBT_RUNTIME_ARTIFACT_PATH,
        failures,
    );
    validate_exact_registry_field(
        "scheduler_wide_runtime_evidence.manifest_path",
        &evidence.manifest_path,
        SCHEDULER_DIRTY_DEBT_RUNTIME_MANIFEST_PATH,
        failures,
    );
    validate_exact_registry_field(
        "scheduler_wide_runtime_evidence.source_registry_boundary",
        &evidence.source_registry_boundary,
        REVIEW_RECEIPT_RUNTIME_BOUNDARY,
        failures,
    );
    validate_unique_nonempty_registry_list(
        "scheduler_wide_runtime_evidence.required_scope_fields",
        &evidence.required_scope_fields,
        failures,
    );
    for required_field in REQUIRED_RUNTIME_SCOPE_FIELDS {
        if !evidence
            .required_scope_fields
            .iter()
            .any(|field| field == required_field)
        {
            failures.push(format!(
                "`{REGISTRY_PATH}` scheduler_wide_runtime_evidence.required_scope_fields must include `{required_field}`"
            ));
        }
    }
    for field in &evidence.required_scope_fields {
        if !REQUIRED_RUNTIME_SCOPE_FIELDS.contains(&field.as_str()) {
            failures.push(format!(
                "`{REGISTRY_PATH}` scheduler_wide_runtime_evidence.required_scope_fields contains unknown field `{field}`"
            ));
        }
    }
}

fn validate_queue_root(root: &Path, queue: &QueueRoot, failures: &mut Vec<String>) {
    if queue.id.trim().is_empty() {
        failures.push("queue root id must not be empty".to_string());
    }
    if !VALID_WORK_CLASSES.contains(&queue.work_class.as_str()) {
        failures.push(format!(
            "queue root `{}` has unknown work_class `{}`",
            queue.id, queue.work_class
        ));
    }
    for domain in &queue.resource_domains {
        if !VALID_RESOURCE_DOMAINS.contains(&domain.as_str()) {
            failures.push(format!(
                "queue root `{}` has unknown resource domain `{domain}`",
                queue.id
            ));
        }
    }
    for cap in &queue.hard_caps {
        if !VALID_HARD_CAPS.contains(&cap.as_str()) {
            failures.push(format!(
                "queue root `{}` has unknown hard cap `{cap}`",
                queue.id
            ));
        }
    }
    for required_cap in VALID_HARD_CAPS {
        if !queue.hard_caps.iter().any(|cap| cap == required_cap) {
            failures.push(format!(
                "queue root `{}` must classify hard cap `{required_cap}`",
                queue.id
            ));
        }
    }

    let rel = Path::new(&queue.path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        failures.push(format!(
            "queue root `{}` path `{}` must be workspace-relative",
            queue.id, queue.path
        ));
        return;
    }

    let path = root.join(rel);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!(
                "queue root `{}` cannot read source `{}`: {err}",
                queue.id, queue.path
            ));
            return;
        }
    };

    for missing in missing_queue_source_semantics(queue, &text) {
        failures.push(format!(
            "queue root `{}` source `{}` does not contain required structured source evidence `{missing}`",
            queue.id, queue.path
        ));
    }

    match package_name_for_path(root, rel) {
        Some(package_name) if package_name == queue.package => {}
        Some(package_name) => failures.push(format!(
            "queue root `{}` declares package `{}`, but `{}` belongs to `{package_name}`",
            queue.id, queue.package, queue.path
        )),
        None => failures.push(format!(
            "queue root `{}` path `{}` is not under a Cargo package root",
            queue.id, queue.path
        )),
    }
}

fn validate_workspace_review_receipts(
    root: &Path,
    registry: &QueueRegistry,
    failures: &mut Vec<String>,
) {
    let receipt_paths = workspace_review_receipt_paths(root, failures);
    if receipt_paths.is_empty() {
        return;
    }
    let Some(claims) = load_claim_registry(root, failures) else {
        return;
    };

    for receipt_rel in receipt_paths {
        if let Some(receipt) = load_review_receipt(root, &receipt_rel, failures) {
            validate_review_receipt(root, &receipt_rel, &receipt, registry, &claims, failures);
        }
    }
}

fn workspace_review_receipt_paths(root: &Path, failures: &mut Vec<String>) -> Vec<PathBuf> {
    let dir = root.join(RECEIPT_DIR);
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(err) => {
            failures.push(format!("could not read `{RECEIPT_DIR}`: {err}"));
            return Vec::new();
        }
    };

    let mut paths = BTreeSet::new();
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                failures.push(format!("could not read `{RECEIPT_DIR}` entry: {err}"));
                continue;
            }
        };
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !file_name.starts_with(RECEIPT_FILE_PREFIX) || !file_name.ends_with(RECEIPT_FILE_SUFFIX)
        {
            continue;
        }
        match path.strip_prefix(root) {
            Ok(rel) => {
                paths.insert(rel.to_path_buf());
            }
            Err(err) => failures.push(format!(
                "could not make receipt path `{}` workspace-relative: {err}",
                path.display()
            )),
        }
    }
    paths.into_iter().collect()
}

fn load_review_receipt(
    root: &Path,
    receipt_rel: &Path,
    failures: &mut Vec<String>,
) -> Option<NoHiddenQueuesReviewReceipt> {
    if !is_workspace_relative(receipt_rel) {
        failures.push(format!(
            "receipt path `{}` must be workspace-relative",
            display_path(receipt_rel)
        ));
        return None;
    }
    let text = match fs::read_to_string(root.join(receipt_rel)) {
        Ok(text) => text,
        Err(err) => {
            failures.push(format!(
                "could not read receipt `{}`: {err}",
                display_path(receipt_rel)
            ));
            return None;
        }
    };
    match toml::from_str::<NoHiddenQueuesReviewReceipt>(&text) {
        Ok(receipt) => Some(receipt),
        Err(err) => {
            failures.push(format!(
                "could not parse receipt `{}`: {err}",
                display_path(receipt_rel)
            ));
            None
        }
    }
}

fn validate_review_receipt(
    root: &Path,
    receipt_rel: &Path,
    receipt: &NoHiddenQueuesReviewReceipt,
    registry: &QueueRegistry,
    claims: &ClaimRegistry,
    failures: &mut Vec<String>,
) {
    let receipt_name = display_path(receipt_rel);
    if receipt.receipt_version != REVIEW_RECEIPT_VERSION {
        failures.push(format!(
            "receipt `{receipt_name}` receipt_version must be {REVIEW_RECEIPT_VERSION}, found {}",
            receipt.receipt_version
        ));
    }
    validate_exact_field(
        &receipt_name,
        "evidence_class",
        &receipt.evidence_class,
        REVIEW_RECEIPT_EVIDENCE_CLASS,
        failures,
    );
    validate_exact_field(
        &receipt_name,
        "evidence_tier",
        &receipt.evidence_tier,
        REVIEW_RECEIPT_EVIDENCE_TIER,
        failures,
    );
    if receipt.issue == 0 {
        failures.push(format!("receipt `{receipt_name}` issue must be nonzero"));
    }
    validate_exact_field(
        &receipt_name,
        "registry_path",
        &receipt.registry_path,
        REGISTRY_PATH,
        failures,
    );
    if receipt.registry_schema_version != registry.schema_version {
        failures.push(format!(
            "receipt `{receipt_name}` registry_schema_version {} does not match `{REGISTRY_PATH}` schema_version {}",
            receipt.registry_schema_version, registry.schema_version
        ));
    }
    validate_exact_field(
        &receipt_name,
        "source_coverage_kind",
        &receipt.source_coverage_kind,
        REVIEW_RECEIPT_SOURCE_COVERAGE_KIND,
        failures,
    );
    validate_exact_field(
        &receipt_name,
        "runtime_artifact_boundary",
        &receipt.runtime_artifact_boundary,
        REVIEW_RECEIPT_RUNTIME_BOUNDARY,
        failures,
    );
    validate_exact_field(
        &receipt_name,
        "decision",
        &receipt.decision,
        REVIEW_RECEIPT_DECISION,
        failures,
    );
    validate_nonempty_field(&receipt_name, "reviewed_at", &receipt.reviewed_at, failures);
    validate_nonempty_field(
        &receipt_name,
        "reviewer.name",
        &receipt.reviewer.name,
        failures,
    );
    validate_nonempty_field(
        &receipt_name,
        "reviewer.role",
        &receipt.reviewer.role,
        failures,
    );
    validate_nonempty_field(&receipt_name, "tool.name", &receipt.tool.name, failures);
    validate_nonempty_field(
        &receipt_name,
        "tool.command",
        &receipt.tool.command,
        failures,
    );
    validate_nonempty_field(
        &receipt_name,
        "tool.version",
        &receipt.tool.version,
        failures,
    );

    let scanned_roots = validate_receipt_scanned_roots(root, &receipt_name, receipt, failures);
    validate_receipt_queue_root_coverage(
        &receipt_name,
        receipt,
        registry,
        &scanned_roots,
        failures,
    );
    validate_receipt_claims(&receipt_name, receipt, claims, failures);
    validate_receipt_out_of_scope(&receipt_name, receipt, claims, failures);
    validate_receipt_non_claims(&receipt_name, receipt, failures);
}

fn validate_receipt_scanned_roots(
    root: &Path,
    receipt_name: &str,
    receipt: &NoHiddenQueuesReviewReceipt,
    failures: &mut Vec<String>,
) -> BTreeSet<String> {
    if receipt.scanned_roots.is_empty() {
        failures.push(format!(
            "receipt `{receipt_name}` must list at least one scanned root"
        ));
    }

    let mut names = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for scanned in &receipt.scanned_roots {
        validate_nonempty_field(receipt_name, "scanned_roots.name", &scanned.name, failures);
        validate_nonempty_field(
            receipt_name,
            "scanned_roots.package",
            &scanned.package,
            failures,
        );
        validate_nonempty_field(receipt_name, "scanned_roots.scan", &scanned.scan, failures);
        if !names.insert(scanned.name.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` has duplicate scanned root name `{}`",
                scanned.name
            ));
        }

        let Some(rel) = workspace_relative_arg(&scanned.path, "scanned root path", failures) else {
            continue;
        };
        let rel_display = display_path(&rel);
        if !paths.insert(rel_display.clone()) {
            failures.push(format!(
                "receipt `{receipt_name}` has duplicate scanned root path `{rel_display}`"
            ));
        }
        if !root.join(&rel).is_dir() {
            failures.push(format!(
                "receipt `{receipt_name}` scanned root `{rel_display}` is not an existing directory"
            ));
        }
        match package_name_for_path(root, &rel) {
            Some(package_name) if package_name == scanned.package => {}
            Some(package_name) => failures.push(format!(
                "receipt `{receipt_name}` scanned root `{rel_display}` declares package `{}`, but belongs to `{package_name}`",
                scanned.package
            )),
            None => failures.push(format!(
                "receipt `{receipt_name}` scanned root `{rel_display}` is not under a Cargo package root"
            )),
        }
    }

    paths
}

fn validate_receipt_queue_root_coverage(
    receipt_name: &str,
    receipt: &NoHiddenQueuesReviewReceipt,
    registry: &QueueRegistry,
    scanned_roots: &BTreeSet<String>,
    failures: &mut Vec<String>,
) {
    if receipt.queue_root_coverage.is_empty() {
        failures.push(format!(
            "receipt `{receipt_name}` must list queue root coverage"
        ));
    }

    let mut registry_by_id = BTreeMap::new();
    for queue in &registry.queue_roots {
        registry_by_id.insert(queue.id.as_str(), queue);
    }

    let mut covered_ids = BTreeSet::new();
    for coverage in &receipt.queue_root_coverage {
        validate_nonempty_field(
            receipt_name,
            "queue_root_coverage.id",
            &coverage.id,
            failures,
        );
        if !covered_ids.insert(coverage.id.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` has duplicate queue root coverage id `{}`",
                coverage.id
            ));
        }
        validate_exact_field(
            receipt_name,
            "queue_root_coverage.coverage",
            &coverage.coverage,
            QUEUE_ROOT_COVERAGE_KIND,
            failures,
        );

        let Some(queue) = registry_by_id.get(coverage.id.as_str()) else {
            failures.push(format!(
                "receipt `{receipt_name}` names unknown queue root `{}`; receipts cannot register hidden-safe queues",
                coverage.id
            ));
            continue;
        };

        validate_registry_match(
            receipt_name,
            &coverage.id,
            "package",
            &coverage.package,
            &queue.package,
            failures,
        );
        validate_registry_match(
            receipt_name,
            &coverage.id,
            "path",
            &coverage.path,
            &queue.path,
            failures,
        );
        validate_registry_match(
            receipt_name,
            &coverage.id,
            "symbol",
            &coverage.symbol,
            &queue.symbol,
            failures,
        );

        let Some(source_root) = workspace_relative_arg(
            &coverage.source_root,
            "queue coverage source_root",
            failures,
        ) else {
            continue;
        };
        let source_root_display = display_path(&source_root);
        if !scanned_roots.contains(&source_root_display) {
            failures.push(format!(
                "receipt `{receipt_name}` queue root `{}` references unscanned source_root `{source_root_display}`",
                coverage.id
            ));
        }
        let queue_path = Path::new(&queue.path);
        if !queue_path.starts_with(&source_root) {
            failures.push(format!(
                "receipt `{receipt_name}` queue root `{}` path `{}` is not under source_root `{source_root_display}`",
                coverage.id, queue.path
            ));
        }
    }

    for queue in &registry.queue_roots {
        if !covered_ids.contains(queue.id.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` is missing queue root coverage for registry id `{}`",
                queue.id
            ));
        }
    }
}

fn validate_receipt_claims(
    receipt_name: &str,
    receipt: &NoHiddenQueuesReviewReceipt,
    claims: &ClaimRegistry,
    failures: &mut Vec<String>,
) {
    let claims_by_id = claims_by_id(claims);
    validate_unique_nonempty_list(
        receipt_name,
        "affected_claim_ids",
        &receipt.affected_claim_ids,
        failures,
    );
    validate_unique_nonempty_list(
        receipt_name,
        "blocked_claim_ids",
        &receipt.blocked_claim_ids,
        failures,
    );

    for claim_id in &receipt.affected_claim_ids {
        if !claims_by_id.contains_key(claim_id.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` references unknown affected claim id `{claim_id}`"
            ));
        }
    }

    let affected: BTreeSet<&str> = receipt
        .affected_claim_ids
        .iter()
        .map(String::as_str)
        .collect();
    for claim_id in &receipt.blocked_claim_ids {
        if !affected.contains(claim_id.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` blocked claim id `{claim_id}` is not listed in affected_claim_ids"
            ));
        }
        match claims_by_id.get(claim_id.as_str()) {
            Some(claim) if claim.status == "blocked" => {}
            Some(claim) => failures.push(format!(
                "receipt `{receipt_name}` blocked claim id `{claim_id}` has registry status `{}`",
                claim.status
            )),
            None => failures.push(format!(
                "receipt `{receipt_name}` references unknown blocked claim id `{claim_id}`"
            )),
        }
    }
}

fn validate_receipt_out_of_scope(
    receipt_name: &str,
    receipt: &NoHiddenQueuesReviewReceipt,
    claims: &ClaimRegistry,
    failures: &mut Vec<String>,
) {
    if receipt.out_of_scope.is_empty() {
        failures.push(format!(
            "receipt `{receipt_name}` must list explicit out-of-scope entries"
        ));
    }
    let claims_by_id = claims_by_id(claims);
    let affected: BTreeSet<&str> = receipt
        .affected_claim_ids
        .iter()
        .map(String::as_str)
        .collect();

    for entry in &receipt.out_of_scope {
        validate_nonempty_field(receipt_name, "out_of_scope.root", &entry.root, failures);
        validate_nonempty_field(receipt_name, "out_of_scope.reason", &entry.reason, failures);
        if entry.owner_issue == 0 {
            failures.push(format!(
                "receipt `{receipt_name}` out_of_scope `{}` owner_issue must be nonzero",
                entry.root
            ));
        }
        validate_unique_nonempty_list(
            receipt_name,
            "out_of_scope.claim_ids",
            &entry.claim_ids,
            failures,
        );
        validate_unique_nonempty_list(
            receipt_name,
            "out_of_scope.does_not_satisfy_evidence_classes",
            &entry.does_not_satisfy_evidence_classes,
            failures,
        );
        if !entry
            .does_not_satisfy_evidence_classes
            .iter()
            .any(|class| class == QUEUE_DEPTH_RUNTIME_ARTIFACT)
        {
            failures.push(format!(
                "receipt `{receipt_name}` out_of_scope `{}` must name `{QUEUE_DEPTH_RUNTIME_ARTIFACT}` as unsatisfied evidence",
                entry.root
            ));
        }
        for claim_id in &entry.claim_ids {
            if !claims_by_id.contains_key(claim_id.as_str()) {
                failures.push(format!(
                    "receipt `{receipt_name}` out_of_scope `{}` references unknown claim id `{claim_id}`",
                    entry.root
                ));
            }
            if !affected.contains(claim_id.as_str()) {
                failures.push(format!(
                    "receipt `{receipt_name}` out_of_scope `{}` claim id `{claim_id}` is not listed in affected_claim_ids",
                    entry.root
                ));
            }
        }
    }
}

fn validate_receipt_non_claims(
    receipt_name: &str,
    receipt: &NoHiddenQueuesReviewReceipt,
    failures: &mut Vec<String>,
) {
    validate_unique_nonempty_list(receipt_name, "non_claims", &receipt.non_claims, failures);
    if !receipt
        .non_claims
        .iter()
        .any(|claim| claim.contains(QUEUE_DEPTH_RUNTIME_ARTIFACT))
    {
        failures.push(format!(
            "receipt `{receipt_name}` non_claims must state that `{QUEUE_DEPTH_RUNTIME_ARTIFACT}` is not satisfied"
        ));
    }
}

fn validate_registry_match(
    receipt_name: &str,
    queue_id: &str,
    field: &str,
    receipt_value: &str,
    registry_value: &str,
    failures: &mut Vec<String>,
) {
    if receipt_value != registry_value {
        failures.push(format!(
            "receipt `{receipt_name}` queue root `{queue_id}` has stale {field} `{receipt_value}`, registry has `{registry_value}`"
        ));
    }
}

fn claims_by_id(claims: &ClaimRegistry) -> BTreeMap<&str, &RegisteredClaim> {
    claims
        .claims
        .iter()
        .map(|claim| (claim.id.as_str(), claim))
        .collect()
}

fn validate_exact_field(
    receipt_name: &str,
    field: &str,
    actual: &str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    if actual != expected {
        failures.push(format!(
            "receipt `{receipt_name}` {field} must be `{expected}`, found `{actual}`"
        ));
    }
}

fn validate_exact_registry_field(
    field: &str,
    actual: &str,
    expected: &str,
    failures: &mut Vec<String>,
) {
    if actual != expected {
        failures.push(format!(
            "`{REGISTRY_PATH}` {field} must be `{expected}`, found `{actual}`"
        ));
    }
}

fn validate_nonempty_field(
    receipt_name: &str,
    field: &str,
    value: &str,
    failures: &mut Vec<String>,
) {
    if value.trim().is_empty() {
        failures.push(format!(
            "receipt `{receipt_name}` {field} must not be empty"
        ));
    }
}

fn validate_unique_nonempty_registry_list(
    field: &str,
    values: &[String],
    failures: &mut Vec<String>,
) {
    if values.is_empty() {
        failures.push(format!("`{REGISTRY_PATH}` {field} must not be empty"));
        return;
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            failures.push(format!(
                "`{REGISTRY_PATH}` {field} must not contain empty entries"
            ));
        }
        if !seen.insert(value.as_str()) {
            failures.push(format!(
                "`{REGISTRY_PATH}` {field} contains duplicate entry `{value}`"
            ));
        }
    }
}

fn validate_unique_nonempty_list(
    receipt_name: &str,
    field: &str,
    values: &[String],
    failures: &mut Vec<String>,
) {
    if values.is_empty() {
        failures.push(format!(
            "receipt `{receipt_name}` {field} must not be empty"
        ));
        return;
    }
    let mut seen = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() {
            failures.push(format!(
                "receipt `{receipt_name}` {field} must not contain empty entries"
            ));
        }
        if !seen.insert(value.as_str()) {
            failures.push(format!(
                "receipt `{receipt_name}` {field} contains duplicate entry `{value}`"
            ));
        }
    }
}

fn workspace_relative_arg(path: &str, label: &str, failures: &mut Vec<String>) -> Option<PathBuf> {
    let rel = PathBuf::from(path);
    if !is_workspace_relative(&rel) {
        failures.push(format!("{label} `{}` must be workspace-relative", path));
        return None;
    }
    Some(rel)
}

fn is_workspace_relative(path: &Path) -> bool {
    !path.as_os_str().is_empty()
        && !path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn scan_source_files(
    root: &Path,
    registry: &QueueRegistry,
    source_files: &[PathBuf],
    failures: &mut Vec<String>,
) {
    let mut roots_by_path: BTreeMap<String, Vec<&QueueRoot>> = BTreeMap::new();
    for queue in &registry.queue_roots {
        roots_by_path
            .entry(queue.path.clone())
            .or_default()
            .push(queue);
    }

    for rel in source_files {
        let rel_display = rel.to_string_lossy().replace('\\', "/");
        let text = match fs::read_to_string(root.join(rel)) {
            Ok(text) => text,
            Err(err) => {
                failures.push(format!(
                    "could not read touched source `{rel_display}`: {err}"
                ));
                continue;
            }
        };
        let candidates = queue_candidate_lines(&text);
        if candidates.is_empty() {
            continue;
        }
        let registered = roots_by_path.get(&rel_display);
        let classified = registered
            .map(|queues| {
                queues
                    .iter()
                    .any(|queue| queue_source_has_required_semantics(queue, &text))
            })
            .unwrap_or(false);
        if classified {
            continue;
        }

        let package = package_name_for_path(root, rel).unwrap_or_else(|| "unknown".to_string());
        for (line, pattern) in candidates {
            failures.push(format!(
                "touched package `{package}` has unclassified queue-like root in `{rel_display}` line {line}: matched `{pattern}`; add `{REGISTRY_PATH}` metadata with path, symbol, admission, and service curve evidence"
            ));
        }
    }
}

fn touched_implementation_files(root: &Path, failures: &mut Vec<String>) -> Vec<PathBuf> {
    let mut files = BTreeSet::new();
    let mut diff_errors = Vec::new();
    let mut successful_diffs = 0usize;
    for args in [
        &[
            "diff",
            "--name-only",
            "--diff-filter=ACMRTUXB",
            "origin/master...HEAD",
        ][..],
        &["diff", "--name-only", "--diff-filter=ACMRTUXB"][..],
        &["diff", "--cached", "--name-only", "--diff-filter=ACMRTUXB"][..],
    ] {
        match git_lines(root, args) {
            Ok(lines) => {
                successful_diffs += 1;
                for line in lines {
                    let path = PathBuf::from(line);
                    if is_implementation_source(&path) {
                        files.insert(path);
                    }
                }
            }
            Err(err) => diff_errors.push(err),
        }
    }
    if successful_diffs == 0 {
        failures.extend(diff_errors);
    }
    files.into_iter().collect()
}

fn scanned_source_files_for_touched_packages(
    root: &Path,
    touched_files: &[PathBuf],
    failures: &mut Vec<String>,
) -> (Vec<PathBuf>, usize) {
    let mut package_roots = BTreeSet::new();
    for rel in touched_files {
        match package_root_for_path(root, rel) {
            Some(package_root) => {
                package_roots.insert(package_root);
            }
            None => failures.push(format!(
                "touched implementation source `{}` is not under a Cargo package root",
                rel.to_string_lossy().replace('\\', "/")
            )),
        }
    }

    let mut source_files = BTreeSet::new();
    for package_root in &package_roots {
        collect_package_source_files(root, package_root, &mut source_files, failures);
    }

    (source_files.into_iter().collect(), package_roots.len())
}

fn collect_package_source_files(
    root: &Path,
    package_root: &Path,
    files: &mut BTreeSet<PathBuf>,
    failures: &mut Vec<String>,
) {
    let source_root = package_root.join("src");
    if !source_root.is_dir() {
        return;
    }
    collect_rs_files(root, &source_root, files, failures);
}

fn collect_rs_files(
    root: &Path,
    dir: &Path,
    files: &mut BTreeSet<PathBuf>,
    failures: &mut Vec<String>,
) {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            failures.push(format!(
                "could not read source directory `{}`: {err}",
                dir.display()
            ));
            return;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                failures.push(format!(
                    "could not read source directory entry in `{}`: {err}",
                    dir.display()
                ));
                continue;
            }
        };
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(root, &path, files, failures);
            continue;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        match path.strip_prefix(root) {
            Ok(rel) => {
                files.insert(rel.to_path_buf());
            }
            Err(err) => failures.push(format!(
                "could not make source path `{}` workspace-relative: {err}",
                path.display()
            )),
        }
    }
}

fn git_lines(root: &Path, args: &[&str]) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .output()
        .map_err(|err| format!("cannot run git {}: {err}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn is_implementation_source(path: &Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    rel.ends_with(".rs")
        && rel.contains("/src/")
        && (rel.starts_with("crates/") || rel.starts_with("apps/") || rel.starts_with("kmod/"))
}

fn queue_candidate_lines(text: &str) -> Vec<(usize, String)> {
    let patterns = queue_patterns();
    let mut candidates = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") || trimmed.starts_with("///") || trimmed.starts_with("//!") {
            continue;
        }
        for pattern in &patterns {
            if line.contains(pattern) {
                candidates.push((index + 1, pattern.clone()));
            }
        }
    }
    candidates
}

fn queue_patterns() -> Vec<String> {
    [
        ("Vec", "Deque<"),
        ("Binary", "Heap<"),
        ("Seg", "Queue<"),
        ("Array", "Queue<"),
        ("mpsc::", "channel"),
        ("sync::", "mpsc"),
        ("crossbeam_channel", "::"),
        ("flume::", ""),
        ("async_channel::", ""),
    ]
    .into_iter()
    .map(|(left, right)| format!("{left}{right}"))
    .collect()
}

fn queue_source_has_required_semantics(queue: &QueueRoot, text: &str) -> bool {
    missing_queue_source_semantics(queue, text).is_empty()
}

fn missing_queue_source_semantics<'a>(queue: &'a QueueRoot, text: &str) -> Vec<&'a str> {
    [
        queue.symbol.as_str(),
        queue.admission.as_str(),
        queue.service_curve.as_str(),
    ]
    .into_iter()
    .filter(|required| !text.contains(required))
    .collect()
}

fn package_name_for_path(root: &Path, rel: &Path) -> Option<String> {
    let package_root = package_root_for_path(root, rel)?;
    manifest_package_name(&package_root.join("Cargo.toml"))
}

fn package_root_for_path(root: &Path, rel: &Path) -> Option<PathBuf> {
    let mut dir = root.join(rel).parent()?.to_path_buf();
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() && manifest_package_name(&manifest).is_some() {
            return Some(dir);
        }
        if dir == root || !dir.pop() {
            return None;
        }
    }
}

fn manifest_package_name(manifest: &Path) -> Option<String> {
    let text = fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('[') && line.ends_with(']') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() == "name" {
            return parse_manifest_string(value.trim());
        }
    }
    None
}

fn parse_manifest_string(value: &str) -> Option<String> {
    let quote = value.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let mut out = String::new();
    for ch in value.chars().skip(1) {
        if ch == quote {
            return Some(out);
        }
        out.push(ch);
    }
    None
}

fn find_workspace_root() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            let text = fs::read_to_string(&manifest).ok()?;
            if text.contains("[workspace]") {
                return Some(dir);
            }
        }
        if !dir.pop() {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn queue_candidate_scan_ignores_comments() {
        let candidates = queue_candidate_lines(
            r#"
// VecDeque<NotAQueue>
struct Root {
    pending: VecDeque<Item>,
}
"#,
        );
        assert_eq!(candidates, vec![(4, "VecDeque<".to_string())]);
    }

    #[test]
    fn implementation_source_scan_stays_on_package_src_roots() {
        assert!(is_implementation_source(Path::new(
            "crates/tidefs-performance-contract/src/lib.rs"
        )));
        assert!(is_implementation_source(Path::new(
            "apps/tidefsctl/src/main.rs"
        )));
        assert!(is_implementation_source(Path::new("kmod/src/lib.rs")));
        assert!(!is_implementation_source(Path::new(
            "crates/tidefs-transport/tests/harness.rs"
        )));
        assert!(!is_implementation_source(Path::new(
            "xtask/tidefs-xtask/src/no_hidden_queues.rs"
        )));
    }

    #[test]
    fn source_scan_classifies_registered_queue_by_semantics() {
        let root = tempfile::tempdir().expect("temp workspace");
        let source_rel = PathBuf::from("crates/tidefs-example/src/lib.rs");
        let source_path = root.path().join(&source_rel);
        fs::create_dir_all(source_path.parent().expect("source parent"))
            .expect("create source dir");
        fs::write(
            &source_path,
            "struct QueueRoot { pending: VecDeque<Item> }\n// admission: AdmissionPermit service_curve: ServiceCurve\n",
        )
        .expect("write source");
        let registry = test_queue_registry();
        let mut failures = Vec::new();

        scan_source_files(root.path(), &registry, &[source_rel], &mut failures);

        assert_eq!(failures, Vec::<String>::new());
    }

    #[test]
    fn source_scan_rejects_registered_queue_without_semantics() {
        let root = tempfile::tempdir().expect("temp workspace");
        let package_root = root.path().join("crates/tidefs-example");
        fs::create_dir_all(package_root.join("src")).expect("create package src");
        fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "tidefs-example"
version = "0.1.0"
edition = "2021"
"#,
        )
        .expect("write manifest");
        let source_rel = PathBuf::from("crates/tidefs-example/src/lib.rs");
        fs::write(
            root.path().join(&source_rel),
            "struct QueueRoot { pending: VecDeque<Item> }\n",
        )
        .expect("write source");
        let registry = test_queue_registry();
        let mut failures = Vec::new();

        scan_source_files(root.path(), &registry, &[source_rel], &mut failures);

        assert!(failures
            .iter()
            .any(|failure| failure.contains("unclassified queue-like root")));
    }

    #[test]
    fn scheduler_runtime_evidence_rejects_weakened_evidence_class() {
        let mut evidence = test_scheduler_wide_runtime_evidence();
        evidence.required_evidence_class = "claims-gate-review".to_string();
        let mut failures = Vec::new();

        validate_scheduler_wide_runtime_evidence(&evidence, &mut failures);

        assert!(failures.iter().any(|failure| failure.contains(
            "scheduler_wide_runtime_evidence.required_evidence_class must be `queue-depth-runtime-artifact`"
        )));
    }

    #[test]
    fn review_receipt_accepts_registered_source_coverage() {
        let root = test_receipt_workspace();
        let failures = validate_test_receipt(root.path(), &valid_receipt());
        assert_eq!(failures, Vec::<String>::new());
    }

    #[test]
    fn review_receipt_rejects_stale_registry_metadata() {
        let root = test_receipt_workspace();
        let receipt = valid_receipt().replace(
            "path = \"crates/tidefs-example/src/lib.rs\"",
            "path = \"crates/tidefs-example/src/old.rs\"",
        );
        let failures = validate_test_receipt(root.path(), &receipt);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("stale path")));
    }

    #[test]
    fn review_receipt_rejects_unknown_queue_root() {
        let root = test_receipt_workspace();
        let receipt = valid_receipt().replace("id = \"example.queue\"", "id = \"example.old\"");
        let failures = validate_test_receipt(root.path(), &receipt);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("names unknown queue root `example.old`")));
    }

    #[test]
    fn review_receipt_rejects_unscanned_source_root() {
        let root = test_receipt_workspace();
        let receipt = valid_receipt().replace(
            "source_root = \"crates/tidefs-example/src\"",
            "source_root = \"crates/tidefs-example/tests\"",
        );
        let failures = validate_test_receipt(root.path(), &receipt);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("references unscanned source_root")));
    }

    #[test]
    fn review_receipt_requires_out_of_scope_reasons() {
        let root = test_receipt_workspace();
        let receipt = valid_receipt().replace(
            "reason = \"runtime queue-depth evidence is owned by issue #498\"",
            "reason = \"\"",
        );
        let failures = validate_test_receipt(root.path(), &receipt);
        assert!(failures
            .iter()
            .any(|failure| failure.contains("out_of_scope.reason must not be empty")));
    }

    fn test_receipt_workspace() -> tempfile::TempDir {
        let root = tempfile::tempdir().expect("temp workspace");
        let package_root = root.path().join("crates/tidefs-example");
        fs::create_dir_all(package_root.join("src")).expect("create package src");
        fs::write(
            package_root.join("Cargo.toml"),
            r#"[package]
name = "tidefs-example"
version = "0.1.0"
edition = "2021"
"#,
        )
        .expect("write manifest");
        fs::write(package_root.join("src/lib.rs"), "pub struct Queue;\n").expect("write source");
        root
    }

    fn validate_test_receipt(root: &Path, text: &str) -> Vec<String> {
        let receipt =
            toml::from_str::<NoHiddenQueuesReviewReceipt>(text).expect("parse test receipt");
        let registry = test_queue_registry();
        let claims = ClaimRegistry {
            claims: vec![RegisteredClaim {
                id: "perf.local.no_unbounded_dirty_debt.v1".to_string(),
                status: "blocked".to_string(),
            }],
        };
        let mut failures = Vec::new();
        validate_review_receipt(
            root,
            Path::new("validation/artifacts/performance/no-hidden-queues-review-receipt.toml"),
            &receipt,
            &registry,
            &claims,
            &mut failures,
        );
        failures
    }

    fn test_queue_registry() -> QueueRegistry {
        let registry = QueueRegistry {
            schema_version: 1,
            scheduler_wide_runtime_evidence: test_scheduler_wide_runtime_evidence(),
            queue_roots: vec![QueueRoot {
                id: "example.queue".to_string(),
                package: "tidefs-example".to_string(),
                path: "crates/tidefs-example/src/lib.rs".to_string(),
                symbol: "Queue".to_string(),
                work_class: "foreground-write".to_string(),
                resource_domains: vec!["queue-slots".to_string()],
                admission: "AdmissionPermit".to_string(),
                service_curve: "ServiceCurve".to_string(),
                hard_caps: vec![
                    "dirty-bytes".to_string(),
                    "dirty-operations".to_string(),
                    "dirty-age".to_string(),
                    "queue-slots".to_string(),
                ],
            }],
        };
        registry
    }

    fn test_scheduler_wide_runtime_evidence() -> SchedulerWideRuntimeEvidence {
        SchedulerWideRuntimeEvidence {
            claim_id: SCHEDULER_DIRTY_DEBT_CLAIM.to_string(),
            required_evidence_class: QUEUE_DEPTH_RUNTIME_ARTIFACT.to_string(),
            artifact_path: SCHEDULER_DIRTY_DEBT_RUNTIME_ARTIFACT_PATH.to_string(),
            manifest_path: SCHEDULER_DIRTY_DEBT_RUNTIME_MANIFEST_PATH.to_string(),
            source_registry_boundary: REVIEW_RECEIPT_RUNTIME_BOUNDARY.to_string(),
            required_scope_fields: REQUIRED_RUNTIME_SCOPE_FIELDS
                .iter()
                .map(|field| field.to_string())
                .collect(),
        }
    }

    fn valid_receipt() -> String {
        r#"receipt_version = 1
evidence_class = "no-hidden-queues-review-receipt"
evidence_tier = "source-registry-review"
issue = 532
registry_path = "validation/performance/no-hidden-queues.toml"
registry_schema_version = 1
source_coverage_kind = "recursive-source-registry-review"
runtime_artifact_boundary = "source-registry-review-only-does-not-satisfy-queue-depth-runtime-artifact"
decision = "claims-remain-blocked"
reviewed_at = "2026-06-18"
affected_claim_ids = [
  "perf.local.no_unbounded_dirty_debt.v1",
]
blocked_claim_ids = [
  "perf.local.no_unbounded_dirty_debt.v1",
]
non_claims = [
  "This receipt does not satisfy queue-depth-runtime-artifact evidence.",
]

[reviewer]
name = "gpt5"
role = "Codex"

[tool]
name = "tidefs-xtask"
command = "cargo run -p tidefs-xtask -- check-no-hidden-queues"
version = "no-hidden-queues-review-receipt-v1"

[[scanned_roots]]
name = "example-src"
package = "tidefs-example"
path = "crates/tidefs-example/src"
scan = "recursive-rust-source-review"

[[queue_root_coverage]]
id = "example.queue"
package = "tidefs-example"
path = "crates/tidefs-example/src/lib.rs"
symbol = "Queue"
source_root = "crates/tidefs-example/src"
coverage = "registered-source-semantics-present"

[[out_of_scope]]
root = "mounted-runtime-queue-depth"
reason = "runtime queue-depth evidence is owned by issue #498"
owner_issue = 498
claim_ids = [
  "perf.local.no_unbounded_dirty_debt.v1",
]
does_not_satisfy_evidence_classes = [
  "queue-depth-runtime-artifact",
]
"#
        .to_string()
    }
}
