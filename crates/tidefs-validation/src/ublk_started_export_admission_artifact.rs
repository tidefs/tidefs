// SPDX-License-Identifier: GPL-2.0-only WITH Linux-syscall-note
use serde::Deserialize;
use std::error::Error;
use std::fmt;
use std::fs;
use std::path::Path;

use crate::ublk_completion_artifact::{
    UBLK_COMPLETION_ARTIFACT_CLAIM_ID, UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS,
};

pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS: &str =
    "runtime-ublk-started-export-admission-artifact";
pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID: &str =
    "ublk.started_export.live_service_loop.v1";
pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_VERIFIER: &str =
    "tidefs-xtask validate-ublk-started-export-admission-artifact";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkStartedExportAdmissionArtifactSummary {
    pub claim_state: String,
    pub start_dev_succeeded: bool,
    pub first_request_serviced: bool,
    pub bounded_no_request_observed: bool,
    pub cleanup_succeeded: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UblkStartedExportAdmissionArtifactError {
    failures: Vec<String>,
}

impl UblkStartedExportAdmissionArtifactError {
    #[must_use]
    pub fn failures(&self) -> &[String] {
        &self.failures
    }
}

impl fmt::Display for UblkStartedExportAdmissionArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "uBLK started-export admission artifact validation failed:"
        )?;
        for failure in &self.failures {
            writeln!(f, "- {failure}")?;
        }
        Ok(())
    }
}

impl Error for UblkStartedExportAdmissionArtifactError {}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UblkStartedExportAdmissionArtifact {
    report_version: u32,
    generated_by: String,
    claim_ids: Vec<String>,
    evidence_class: String,
    evidence_scope: String,
    scenario: String,
    queue_geometry: QueueGeometry,
    host_preflight: HostPreflight,
    control_chain: ControlChain,
    data_queue: DataQueue,
    fetch_req_coverage: FetchReqCoverage,
    start_dev: StartDev,
    service_loop: ServiceLoop,
    completion_authority: CompletionAuthority,
    cleanup: Cleanup,
    admission_verifier: AdmissionVerifier,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct QueueGeometry {
    nr_hw_queues: u16,
    queue_depth: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostPreflight {
    kernel_release: String,
    host_preflight_admitted: bool,
    control_open_attempted: bool,
    control_opened: bool,
    control_open_error_class: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlChain {
    feature_probe_attempted: bool,
    feature_probe_completed: bool,
    feature_mask: Option<u64>,
    required_features_available: bool,
    add_dev_attempted: bool,
    add_dev_completed: bool,
    add_dev_dev_id: Option<u32>,
    set_params_attempted: bool,
    set_params_completed: bool,
    set_params_block_size_bytes: Option<u64>,
    set_params_block_count: Option<u64>,
    set_params_dev_sectors: Option<u64>,
    set_params_errno: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DataQueue {
    open_attempted: bool,
    opened: bool,
    path: Option<String>,
    runtime_live_at_start: bool,
    open_errno: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FetchReqCoverage {
    submission_attempted: bool,
    submission_completed: bool,
    required_commands: u32,
    submitted_commands: u32,
    all_queue_tag_slots_covered: bool,
    first_qid: Option<u16>,
    first_tag: Option<u16>,
    last_qid: Option<u16>,
    last_tag: Option<u16>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartDev {
    attempted: bool,
    succeeded: bool,
    state: String,
    refusal_class: Option<String>,
    errno: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceLoop {
    owned: bool,
    attempted: bool,
    completed_iterations: u64,
    cqes_processed: u64,
    first_request_observation: String,
    first_request_serviced: bool,
    bounded_no_request_observed: bool,
    commit_and_fetch_submitted: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletionAuthority {
    claim_id: String,
    evidence_class: String,
    verifier: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    shutdown_graceful: bool,
    drain_cqes_processed: u64,
    drain_iterations: u64,
    drain_timed_out: bool,
    drain_hung_io_count: u64,
    final_flush_completed: bool,
    stop_dev_attempted: bool,
    stop_dev_succeeded: bool,
    del_dev_attempted: bool,
    del_dev_succeeded: bool,
    del_dev_errno: Option<i32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionVerifier {
    verifier: String,
    claim_state: String,
    failure_class: Option<String>,
    start_dev_preconditions_satisfied: bool,
    request_observation_satisfied: bool,
    cleanup_succeeded: bool,
}

#[must_use]
pub fn validate_ublk_started_export_admission_artifact_json(
    text: &str,
) -> Result<UblkStartedExportAdmissionArtifactSummary, UblkStartedExportAdmissionArtifactError> {
    let artifact = match serde_json::from_str::<UblkStartedExportAdmissionArtifact>(text) {
        Ok(artifact) => artifact,
        Err(error) => {
            return Err(UblkStartedExportAdmissionArtifactError {
                failures: vec![format!("artifact JSON does not match schema: {error}")],
            });
        }
    };
    validate_ublk_started_export_admission_artifact(artifact)
}

pub fn validate_ublk_started_export_admission_artifact_path(
    path: impl AsRef<Path>,
) -> Result<UblkStartedExportAdmissionArtifactSummary, UblkStartedExportAdmissionArtifactError> {
    let path = path.as_ref();
    let text =
        fs::read_to_string(path).map_err(|error| UblkStartedExportAdmissionArtifactError {
            failures: vec![format!("read `{}`: {error}", path.display())],
        })?;
    validate_ublk_started_export_admission_artifact_json(&text)
}

fn validate_ublk_started_export_admission_artifact(
    artifact: UblkStartedExportAdmissionArtifact,
) -> Result<UblkStartedExportAdmissionArtifactSummary, UblkStartedExportAdmissionArtifactError> {
    let mut failures = Vec::new();
    validate_static_fields(&artifact, &mut failures);
    validate_chain_invariants(&artifact, &mut failures);

    let fetch_req_all_slots_covered = exact_fetch_req_coverage(&artifact);
    if artifact.fetch_req_coverage.all_queue_tag_slots_covered && !fetch_req_all_slots_covered {
        failures.push(
            "fetch_req_coverage.all_queue_tag_slots_covered must cover configured queue/tag geometry"
                .to_string(),
        );
    }

    let start_dev_preconditions_satisfied =
        start_dev_preconditions_satisfied(&artifact, fetch_req_all_slots_covered);
    if artifact.start_dev.attempted && !start_dev_preconditions_satisfied {
        failures.push(
            "START_DEV attempted without complete live queue/tag FETCH_REQ coverage".to_string(),
        );
    }
    match (
        artifact.start_dev.attempted,
        artifact.start_dev.succeeded,
        artifact.start_dev.state.as_str(),
    ) {
        (true, true, "succeeded") => {}
        (true, false, "refused") => {}
        (false, false, "not_attempted") => {}
        _ => failures
            .push("start_dev attempted/succeeded booleans must match start_dev.state".to_string()),
    }
    if artifact.start_dev.succeeded
        && (!start_dev_preconditions_satisfied
            || artifact.start_dev.refusal_class.is_some()
            || artifact.start_dev.errno.is_some())
    {
        failures.push(
            "successful START_DEV must have complete preconditions and no refusal/errno"
                .to_string(),
        );
    }
    if artifact.start_dev.attempted
        && !artifact.start_dev.succeeded
        && artifact.start_dev.refusal_class.is_none()
    {
        failures.push("refused START_DEV must carry a named refusal class".to_string());
    }
    if !artifact.start_dev.attempted
        && !start_dev_preconditions_satisfied
        && artifact.start_dev.refusal_class.is_none()
    {
        failures.push("early START_DEV refusal must carry a named refusal class".to_string());
    }
    if artifact.service_loop.owned
        && !(artifact.start_dev.succeeded && start_dev_preconditions_satisfied)
    {
        failures.push(
            "service_loop.owned requires successful START_DEV and complete preconditions"
                .to_string(),
        );
    }
    if artifact.start_dev.succeeded && !artifact.service_loop.owned {
        failures.push("successful START_DEV must bind a daemon-owned service loop".to_string());
    }
    if artifact.start_dev.succeeded && !artifact.service_loop.attempted {
        failures.push("successful START_DEV must attempt the data-queue service loop".to_string());
    }
    if artifact.start_dev.succeeded && artifact.service_loop.completed_iterations == 0 {
        failures.push(
            "successful START_DEV must record at least one service-loop iteration".to_string(),
        );
    }
    if artifact.service_loop.cqes_processed > 0 && artifact.service_loop.completed_iterations == 0 {
        failures.push("service_loop.cqes_processed requires completed_iterations".to_string());
    }

    let request_observation_satisfied = request_observation_satisfied(&artifact);
    if artifact.start_dev.succeeded && !request_observation_satisfied {
        failures.push(
            "successful START_DEV requires one serviced request or a bounded no-request observation"
                .to_string(),
        );
    }
    if artifact.service_loop.first_request_serviced
        && (artifact.service_loop.commit_and_fetch_submitted == 0
            || artifact.service_loop.cqes_processed == 0
            || artifact.service_loop.first_request_observation != "serviced_request")
    {
        failures.push(
            "first_request_serviced requires CQE processing, COMMIT_AND_FETCH, and serviced_request observation"
                .to_string(),
        );
    }
    if artifact.service_loop.bounded_no_request_observed
        && (artifact.service_loop.commit_and_fetch_submitted != 0
            || artifact.service_loop.first_request_observation != "bounded_no_request")
    {
        failures.push(
            "bounded_no_request_observed requires zero COMMIT_AND_FETCH submissions".to_string(),
        );
    }
    if artifact.service_loop.first_request_serviced
        && artifact.service_loop.bounded_no_request_observed
    {
        failures.push(
            "first_request_serviced and bounded_no_request_observed are mutually exclusive"
                .to_string(),
        );
    }

    validate_cleanup(&artifact, &mut failures);

    let cleanup_succeeded = cleanup_succeeded(&artifact);
    let claim_state = if !artifact.start_dev.succeeded {
        "refused"
    } else if !cleanup_succeeded {
        "cleanup_failed"
    } else if artifact.service_loop.first_request_serviced {
        "started_request_serviced"
    } else {
        "started_bounded_no_request"
    };
    let failure_class = match claim_state {
        "refused" => artifact.start_dev.refusal_class.clone(),
        "cleanup_failed" => Some("cleanup_failed".to_string()),
        _ => None,
    };

    validate_embedded_verifier(
        &artifact,
        claim_state,
        failure_class.as_deref(),
        start_dev_preconditions_satisfied,
        request_observation_satisfied,
        cleanup_succeeded,
        &mut failures,
    );

    if !failures.is_empty() {
        return Err(UblkStartedExportAdmissionArtifactError { failures });
    }

    Ok(UblkStartedExportAdmissionArtifactSummary {
        claim_state: claim_state.to_string(),
        start_dev_succeeded: artifact.start_dev.succeeded,
        first_request_serviced: artifact.service_loop.first_request_serviced,
        bounded_no_request_observed: artifact.service_loop.bounded_no_request_observed,
        cleanup_succeeded,
    })
}

fn validate_static_fields(
    artifact: &UblkStartedExportAdmissionArtifact,
    failures: &mut Vec<String>,
) {
    if artifact.report_version != 1 {
        failures.push(format!(
            "report_version must be 1, found {}",
            artifact.report_version
        ));
    }
    if artifact.generated_by.trim().is_empty() {
        failures.push("generated_by must not be empty".to_string());
    }
    if artifact.evidence_class != UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS {
        failures.push(format!(
            "evidence_class must be `{UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS}`, found `{}`",
            artifact.evidence_class
        ));
    }
    if !artifact
        .claim_ids
        .iter()
        .any(|claim_id| claim_id == UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID)
    {
        failures.push(format!(
            "claim_ids must include `{UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID}`"
        ));
    }
    if !artifact
        .claim_ids
        .iter()
        .any(|claim_id| claim_id == UBLK_COMPLETION_ARTIFACT_CLAIM_ID)
    {
        failures.push(format!(
            "claim_ids must include completion authority `{UBLK_COMPLETION_ARTIFACT_CLAIM_ID}`"
        ));
    }
    if artifact.evidence_scope.trim().is_empty() {
        failures.push("evidence_scope must not be empty".to_string());
    }
    if artifact.scenario.trim().is_empty() {
        failures.push("scenario must not be empty".to_string());
    }
    if artifact.host_preflight.kernel_release.trim().is_empty() {
        failures.push("host_preflight.kernel_release must not be empty".to_string());
    }
    if artifact
        .host_preflight
        .control_open_error_class
        .as_ref()
        .is_some_and(|error_class| error_class.trim().is_empty())
    {
        failures.push("host_preflight.control_open_error_class must not be empty".to_string());
    }
    if artifact.queue_geometry.nr_hw_queues == 0 {
        failures.push("queue_geometry.nr_hw_queues must be nonzero".to_string());
    }
    if artifact.queue_geometry.queue_depth == 0 {
        failures.push("queue_geometry.queue_depth must be nonzero".to_string());
    }
    if artifact.completion_authority.claim_id != UBLK_COMPLETION_ARTIFACT_CLAIM_ID {
        failures.push(format!(
            "completion_authority.claim_id must be `{UBLK_COMPLETION_ARTIFACT_CLAIM_ID}`"
        ));
    }
    if artifact.completion_authority.evidence_class != UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS {
        failures.push(format!(
            "completion_authority.evidence_class must be `{UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS}`"
        ));
    }
    if artifact.completion_authority.verifier != "tidefs-xtask validate-ublk-completion-artifact" {
        failures.push(
            "completion_authority.verifier must be tidefs-xtask validate-ublk-completion-artifact"
                .to_string(),
        );
    }
}

fn validate_chain_invariants(
    artifact: &UblkStartedExportAdmissionArtifact,
    failures: &mut Vec<String>,
) {
    if artifact.host_preflight.control_opened && !artifact.host_preflight.control_open_attempted {
        failures.push("control_opened requires control_open_attempted".to_string());
    }
    if artifact.host_preflight.control_opened
        && artifact.host_preflight.control_open_error_class.is_some()
    {
        failures.push("control_opened must not carry control_open_error_class".to_string());
    }
    if artifact.host_preflight.control_open_attempted
        && !artifact.host_preflight.control_opened
        && artifact.host_preflight.control_open_error_class.is_none()
    {
        failures.push("failed control open must carry control_open_error_class".to_string());
    }
    if artifact.control_chain.feature_probe_completed
        && !artifact.control_chain.feature_probe_attempted
    {
        failures.push("feature_probe_completed requires feature_probe_attempted".to_string());
    }
    if artifact.control_chain.feature_probe_completed
        && artifact.control_chain.feature_mask.is_none()
    {
        failures.push("feature_probe_completed requires feature_mask".to_string());
    }
    if artifact.control_chain.required_features_available
        && !artifact.control_chain.feature_probe_completed
    {
        failures.push("required_features_available requires feature_probe_completed".to_string());
    }
    if artifact.control_chain.add_dev_attempted
        && !(artifact.host_preflight.host_preflight_admitted
            && artifact.host_preflight.control_opened
            && artifact.control_chain.required_features_available)
    {
        failures.push(
            "add_dev_attempted requires admitted host, open control, and required features"
                .to_string(),
        );
    }
    if artifact.control_chain.add_dev_completed
        && !(artifact.host_preflight.host_preflight_admitted
            && artifact.host_preflight.control_opened
            && artifact.control_chain.required_features_available
            && artifact.control_chain.add_dev_dev_id.is_some())
    {
        failures.push(
            "add_dev_completed requires admitted host, open control, required features, and device id"
                .to_string(),
        );
    }
    if artifact.control_chain.set_params_completed
        && !(artifact.control_chain.set_params_attempted
            && artifact.control_chain.add_dev_completed
            && artifact.control_chain.set_params_block_size_bytes.is_some()
            && artifact.control_chain.set_params_block_count.is_some()
            && artifact.control_chain.set_params_dev_sectors.is_some())
    {
        failures.push(
            "set_params_completed requires attempted SET_PARAMS, ADD_DEV completion, and geometry"
                .to_string(),
        );
    }
    if artifact.control_chain.set_params_completed
        && artifact.control_chain.set_params_errno.is_some()
    {
        failures.push("set_params_completed must not carry set_params_errno".to_string());
    }
    if artifact.control_chain.set_params_attempted
        && !artifact.control_chain.set_params_completed
        && artifact.control_chain.set_params_errno.is_none()
    {
        failures.push("failed SET_PARAMS must carry set_params_errno".to_string());
    }
    if artifact.data_queue.opened
        && !(artifact.data_queue.open_attempted
            && artifact.control_chain.set_params_completed
            && artifact.data_queue.path.is_some())
    {
        failures.push(
            "data_queue.opened requires attempted open, SET_PARAMS completion, and path"
                .to_string(),
        );
    }
    if artifact.data_queue.opened && artifact.data_queue.open_errno.is_some() {
        failures.push("data_queue.opened must not carry open_errno".to_string());
    }
    if artifact.data_queue.open_attempted
        && !artifact.data_queue.opened
        && artifact.data_queue.open_errno.is_none()
    {
        failures.push("failed data-queue open must carry open_errno".to_string());
    }
    if artifact.fetch_req_coverage.submission_completed
        && !(artifact.fetch_req_coverage.submission_attempted
            && artifact.data_queue.opened
            && artifact.data_queue.runtime_live_at_start)
    {
        failures.push(
            "fetch_req submission completion requires attempted submission and live data-queue runtime"
                .to_string(),
        );
    }
}

fn exact_fetch_req_coverage(artifact: &UblkStartedExportAdmissionArtifact) -> bool {
    let expected = u32::from(artifact.queue_geometry.nr_hw_queues)
        * u32::from(artifact.queue_geometry.queue_depth);
    artifact.fetch_req_coverage.submission_completed
        && artifact.fetch_req_coverage.required_commands > 0
        && artifact.fetch_req_coverage.required_commands == expected
        && artifact.fetch_req_coverage.submitted_commands
            == artifact.fetch_req_coverage.required_commands
        && artifact.fetch_req_coverage.first_qid == Some(0)
        && artifact.fetch_req_coverage.first_tag == Some(0)
        && artifact.fetch_req_coverage.last_qid
            == Some(artifact.queue_geometry.nr_hw_queues.saturating_sub(1))
        && artifact.fetch_req_coverage.last_tag
            == Some(artifact.queue_geometry.queue_depth.saturating_sub(1))
        && artifact.data_queue.runtime_live_at_start
}

fn start_dev_preconditions_satisfied(
    artifact: &UblkStartedExportAdmissionArtifact,
    fetch_req_all_slots_covered: bool,
) -> bool {
    artifact.host_preflight.host_preflight_admitted
        && artifact.host_preflight.control_opened
        && artifact.control_chain.required_features_available
        && artifact.control_chain.add_dev_completed
        && artifact.control_chain.set_params_completed
        && artifact.data_queue.opened
        && artifact.data_queue.runtime_live_at_start
        && artifact.fetch_req_coverage.all_queue_tag_slots_covered
        && fetch_req_all_slots_covered
}

fn request_observation_satisfied(artifact: &UblkStartedExportAdmissionArtifact) -> bool {
    if !artifact.start_dev.succeeded {
        return false;
    }
    artifact.service_loop.attempted
        && ((artifact.service_loop.first_request_serviced
            && !artifact.service_loop.bounded_no_request_observed
            && artifact.service_loop.commit_and_fetch_submitted > 0
            && artifact.service_loop.first_request_observation == "serviced_request")
            || (artifact.service_loop.bounded_no_request_observed
                && !artifact.service_loop.first_request_serviced
                && artifact.service_loop.commit_and_fetch_submitted == 0
                && artifact.service_loop.first_request_observation == "bounded_no_request"))
}

fn validate_cleanup(artifact: &UblkStartedExportAdmissionArtifact, failures: &mut Vec<String>) {
    if !artifact.cleanup.shutdown_graceful
        && (artifact.cleanup.drain_cqes_processed != 0
            || artifact.cleanup.drain_iterations != 0
            || artifact.cleanup.drain_timed_out
            || artifact.cleanup.drain_hung_io_count != 0
            || artifact.cleanup.final_flush_completed)
    {
        failures.push(
            "non-graceful shutdown must not report drain or final-flush completion".to_string(),
        );
    }
    if artifact.cleanup.drain_cqes_processed > 0 && artifact.cleanup.drain_iterations == 0 {
        failures.push("drain_cqes_processed requires drain_iterations".to_string());
    }
    if artifact.cleanup.drain_hung_io_count > 0 && !artifact.cleanup.shutdown_graceful {
        failures.push("drain_hung_io_count requires graceful shutdown drain".to_string());
    }
    if artifact.cleanup.final_flush_completed && !artifact.cleanup.shutdown_graceful {
        failures.push("final_flush_completed requires graceful shutdown".to_string());
    }
    if artifact.cleanup.stop_dev_succeeded && !artifact.cleanup.stop_dev_attempted {
        failures.push("stop_dev_succeeded requires stop_dev_attempted".to_string());
    }
    if artifact.cleanup.del_dev_succeeded && !artifact.cleanup.del_dev_attempted {
        failures.push("del_dev_succeeded requires del_dev_attempted".to_string());
    }
    if artifact.cleanup.del_dev_succeeded && artifact.cleanup.del_dev_errno.is_some() {
        failures.push("del_dev_succeeded must not carry del_dev_errno".to_string());
    }
    if artifact.control_chain.add_dev_completed && !artifact.cleanup.del_dev_attempted {
        failures.push("ADD_DEV completion must report DEL_DEV cleanup attempt".to_string());
    }
}

fn cleanup_succeeded(artifact: &UblkStartedExportAdmissionArtifact) -> bool {
    !artifact.control_chain.add_dev_completed
        || (artifact.cleanup.del_dev_attempted
            && artifact.cleanup.del_dev_succeeded
            && artifact.cleanup.del_dev_errno.is_none())
}

fn validate_embedded_verifier(
    artifact: &UblkStartedExportAdmissionArtifact,
    claim_state: &str,
    failure_class: Option<&str>,
    start_dev_preconditions_satisfied: bool,
    request_observation_satisfied: bool,
    cleanup_succeeded: bool,
    failures: &mut Vec<String>,
) {
    if artifact.admission_verifier.verifier != UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_VERIFIER {
        failures.push(format!(
            "admission_verifier.verifier must be `{UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_VERIFIER}`"
        ));
    }
    if artifact.admission_verifier.claim_state != claim_state {
        failures.push(format!(
            "admission_verifier.claim_state must be `{claim_state}`, found `{}`",
            artifact.admission_verifier.claim_state
        ));
    }
    if artifact.admission_verifier.failure_class.as_deref() != failure_class {
        failures.push(format!(
            "admission_verifier.failure_class must be `{}`, found `{}`",
            failure_class.unwrap_or("null"),
            artifact
                .admission_verifier
                .failure_class
                .as_deref()
                .unwrap_or("null")
        ));
    }
    if artifact
        .admission_verifier
        .start_dev_preconditions_satisfied
        != start_dev_preconditions_satisfied
    {
        failures.push(
            "admission_verifier.start_dev_preconditions_satisfied does not match artifact"
                .to_string(),
        );
    }
    if artifact.admission_verifier.request_observation_satisfied != request_observation_satisfied {
        failures.push(
            "admission_verifier.request_observation_satisfied does not match artifact".to_string(),
        );
    }
    if artifact.admission_verifier.cleanup_succeeded != cleanup_succeeded {
        failures.push("admission_verifier.cleanup_succeeded does not match artifact".to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_artifact() -> String {
        r#"{
  "report_version": 1,
  "generated_by": "tidefs-block-volume-adapter-daemon",
  "claim_ids": [
    "ublk.started_export.live_service_loop.v1",
    "ublk.qid_tag.exactly_once_completion.v1"
  ],
  "evidence_class": "runtime-ublk-started-export-admission-artifact",
  "evidence_scope": "bounded started uBLK export admission and daemon-owned data-queue service-loop trace",
  "scenario": "qemu-ublk-smoke",
  "queue_geometry": {
    "nr_hw_queues": 1,
    "queue_depth": 2
  },
  "host_preflight": {
    "kernel_release": "7.0.0-test",
    "host_preflight_admitted": true,
    "control_open_attempted": true,
    "control_opened": true,
    "control_open_error_class": null
  },
  "control_chain": {
    "feature_probe_attempted": true,
    "feature_probe_completed": true,
    "feature_mask": 192,
    "required_features_available": true,
    "add_dev_attempted": true,
    "add_dev_completed": true,
    "add_dev_dev_id": 0,
    "set_params_attempted": true,
    "set_params_completed": true,
    "set_params_block_size_bytes": 4096,
    "set_params_block_count": 128,
    "set_params_dev_sectors": 1024,
    "set_params_errno": null
  },
  "data_queue": {
    "open_attempted": true,
    "opened": true,
    "path": "/dev/ublkc0",
    "runtime_live_at_start": true,
    "open_errno": null
  },
  "fetch_req_coverage": {
    "submission_attempted": true,
    "submission_completed": true,
    "required_commands": 2,
    "submitted_commands": 2,
    "all_queue_tag_slots_covered": true,
    "first_qid": 0,
    "first_tag": 0,
    "last_qid": 0,
    "last_tag": 1
  },
  "start_dev": {
    "attempted": true,
    "succeeded": true,
    "state": "succeeded",
    "refusal_class": null,
    "errno": null
  },
  "service_loop": {
    "owned": true,
    "attempted": true,
    "completed_iterations": 3,
    "cqes_processed": 4,
    "first_request_observation": "serviced_request",
    "first_request_serviced": true,
    "bounded_no_request_observed": false,
    "commit_and_fetch_submitted": 1
  },
  "completion_authority": {
    "claim_id": "ublk.qid_tag.exactly_once_completion.v1",
    "evidence_class": "runtime-ublk-completion-artifact",
    "verifier": "tidefs-xtask validate-ublk-completion-artifact"
  },
  "cleanup": {
    "shutdown_graceful": true,
    "drain_cqes_processed": 1,
    "drain_iterations": 1,
    "drain_timed_out": false,
    "drain_hung_io_count": 0,
    "final_flush_completed": true,
    "stop_dev_attempted": true,
    "stop_dev_succeeded": true,
    "del_dev_attempted": true,
    "del_dev_succeeded": true,
    "del_dev_errno": null
  },
  "admission_verifier": {
    "verifier": "tidefs-xtask validate-ublk-started-export-admission-artifact",
    "claim_state": "started_request_serviced",
    "failure_class": null,
    "start_dev_preconditions_satisfied": true,
    "request_observation_satisfied": true,
    "cleanup_succeeded": true
  }
}"#
        .to_string()
    }

    fn assert_invalid_contains(text: String, needle: &str) {
        let error =
            validate_ublk_started_export_admission_artifact_json(&text).expect_err("invalid");
        assert!(
            error
                .failures()
                .iter()
                .any(|failure| failure.contains(needle)),
            "expected failure containing `{needle}`, got {error:?}"
        );
    }

    #[test]
    fn accepts_started_export_admission_artifact() {
        let summary = validate_ublk_started_export_admission_artifact_json(&valid_artifact())
            .expect("valid artifact");
        assert_eq!(summary.claim_state, "started_request_serviced");
        assert!(summary.start_dev_succeeded);
        assert!(summary.first_request_serviced);
        assert!(!summary.bounded_no_request_observed);
        assert!(summary.cleanup_succeeded);
    }

    #[test]
    fn rejects_start_dev_without_live_queue_ownership() {
        let text = valid_artifact().replace(
            r#""runtime_live_at_start": true"#,
            r#""runtime_live_at_start": false"#,
        );
        assert_invalid_contains(text, "START_DEV attempted without complete live queue/tag");
    }

    #[test]
    fn rejects_incomplete_queue_tag_coverage() {
        let text = valid_artifact().replace(r#""last_tag": 1"#, r#""last_tag": 0"#);
        assert_invalid_contains(text, "configured queue/tag geometry");
    }

    #[test]
    fn rejects_started_export_without_request_observation() {
        let text = valid_artifact()
            .replace(
                r#""first_request_observation": "serviced_request""#,
                r#""first_request_observation": "no_request_observation_missing""#,
            )
            .replace(
                r#""first_request_serviced": true"#,
                r#""first_request_serviced": false"#,
            )
            .replace(
                r#""commit_and_fetch_submitted": 1"#,
                r#""commit_and_fetch_submitted": 0"#,
            );
        assert_invalid_contains(
            text,
            "one serviced request or a bounded no-request observation",
        );
    }

    #[test]
    fn accepts_cleanup_failure_as_visible_claim_state() {
        let text = valid_artifact()
            .replace(
                r#""del_dev_succeeded": true"#,
                r#""del_dev_succeeded": false"#,
            )
            .replace(r#""del_dev_errno": null"#, r#""del_dev_errno": 16"#)
            .replace(
                r#""claim_state": "started_request_serviced""#,
                r#""claim_state": "cleanup_failed""#,
            )
            .replace(
                r#""failure_class": null"#,
                r#""failure_class": "cleanup_failed""#,
            )
            .replace(
                r#""cleanup_succeeded": true"#,
                r#""cleanup_succeeded": false"#,
            );
        let summary =
            validate_ublk_started_export_admission_artifact_json(&text).expect("cleanup visible");
        assert_eq!(summary.claim_state, "cleanup_failed");
        assert!(!summary.cleanup_succeeded);
    }

    #[test]
    fn rejects_embedded_verifier_mismatch() {
        let text = valid_artifact().replace(
            r#""claim_state": "started_request_serviced""#,
            r#""claim_state": "refused""#,
        );
        assert_invalid_contains(text, "admission_verifier.claim_state");
    }
}
