use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::ublk_completion::{
    UBLK_COMPLETION_ARTIFACT_CLAIM_ID, UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS,
};

pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_ENV: &str = "TIDEFS_UBLK_STARTED_EXPORT_ARTIFACT";
pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS: &str =
    "runtime-ublk-started-export-admission-artifact";
pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID: &str =
    "ublk.started_export.live_service_loop.v1";
pub const UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_VERIFIER: &str =
    "tidefs-xtask validate-ublk-started-export-admission-artifact";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UblkStartedExportAdmissionArtifact {
    pub nr_hw_queues: u16,
    pub queue_depth: u16,
    pub kernel_release: String,
    pub host_preflight_admitted: bool,
    pub control_open_attempted: bool,
    pub control_opened: bool,
    pub control_open_error_class: Option<String>,
    pub feature_probe_attempted: bool,
    pub feature_probe_completed: bool,
    pub feature_mask: Option<u64>,
    pub required_features_available: bool,
    pub add_dev_attempted: bool,
    pub add_dev_completed: bool,
    pub add_dev_dev_id: Option<u32>,
    pub set_params_attempted: bool,
    pub set_params_completed: bool,
    pub set_params_block_size_bytes: Option<u64>,
    pub set_params_block_count: Option<u64>,
    pub set_params_dev_sectors: Option<u64>,
    pub set_params_errno: Option<i32>,
    pub data_queue_open_attempted: bool,
    pub data_queue_opened: bool,
    pub data_queue_path: Option<PathBuf>,
    pub data_queue_runtime_live_at_start: bool,
    pub data_queue_open_errno: Option<i32>,
    pub fetch_req_submission_attempted: bool,
    pub fetch_req_submission_completed: bool,
    pub fetch_req_required_commands: u32,
    pub fetch_req_submitted_commands: u32,
    pub fetch_req_all_queue_tag_slots_covered: bool,
    pub fetch_req_first_qid: Option<u16>,
    pub fetch_req_first_tag: Option<u16>,
    pub fetch_req_last_qid: Option<u16>,
    pub fetch_req_last_tag: Option<u16>,
    pub start_dev_attempted: bool,
    pub start_dev_succeeded: bool,
    pub start_dev_state: String,
    pub start_dev_refusal_class: Option<String>,
    pub start_dev_errno: Option<i32>,
    pub service_loop_owned: bool,
    pub service_loop_attempted: bool,
    pub service_loop_completed_iterations: u64,
    pub service_loop_cqes_processed: u64,
    pub first_request_observation: String,
    pub first_request_serviced: bool,
    pub bounded_no_request_observed: bool,
    pub commit_and_fetch_submitted: u64,
    pub completion_authority_claim_id: &'static str,
    pub completion_authority_evidence_class: &'static str,
    pub shutdown_graceful: bool,
    pub drain_cqes_processed: u64,
    pub drain_iterations: u64,
    pub drain_timed_out: bool,
    pub drain_hung_io_count: u64,
    pub final_flush_completed: bool,
    pub stop_dev_attempted: bool,
    pub stop_dev_succeeded: bool,
    pub del_dev_attempted: bool,
    pub del_dev_succeeded: bool,
    pub del_dev_errno: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct UblkStartedExportAdmissionVerification {
    pub claim_state: &'static str,
    pub failure_class: Option<String>,
    pub start_dev_preconditions_satisfied: bool,
    pub request_observation_satisfied: bool,
    pub cleanup_succeeded: bool,
}

impl UblkStartedExportAdmissionArtifact {
    #[must_use]
    pub(crate) fn artifact_path_from_env() -> Option<PathBuf> {
        env::var_os(UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_ENV)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
    }

    pub(crate) fn write_if_enabled(&self) -> io::Result<Option<PathBuf>> {
        let Some(path) = Self::artifact_path_from_env() else {
            return Ok(None);
        };
        let verification = self.verify().map_err(|message| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("started-export admission artifact failed verifier: {message}"),
            )
        })?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, self.to_json_with_verification(&verification))?;
        Ok(Some(path))
    }

    pub(crate) fn verify(&self) -> Result<UblkStartedExportAdmissionVerification, String> {
        let mut failures = Vec::new();

        if self.nr_hw_queues == 0 {
            failures.push("nr_hw_queues must be nonzero".to_string());
        }
        if self.queue_depth == 0 {
            failures.push("queue_depth must be nonzero".to_string());
        }
        if self.kernel_release.trim().is_empty() {
            failures.push("kernel_release must not be empty".to_string());
        }
        if self
            .control_open_error_class
            .as_ref()
            .is_some_and(|error_class| error_class.trim().is_empty())
        {
            failures.push("control_open_error_class must not be empty".to_string());
        }
        if self.control_opened && !self.control_open_attempted {
            failures.push("control_opened requires control_open_attempted".to_string());
        }
        if self.control_opened && self.control_open_error_class.is_some() {
            failures.push("control_opened must not carry control_open_error_class".to_string());
        }
        if self.control_open_attempted
            && !self.control_opened
            && self.control_open_error_class.is_none()
        {
            failures.push("failed control open must carry control_open_error_class".to_string());
        }
        if self.feature_probe_completed && !self.feature_probe_attempted {
            failures.push("feature_probe_completed requires feature_probe_attempted".to_string());
        }
        if self.feature_probe_completed && self.feature_mask.is_none() {
            failures.push("feature_probe_completed requires feature_mask".to_string());
        }
        if self.required_features_available && !self.feature_probe_completed {
            failures
                .push("required_features_available requires feature_probe_completed".to_string());
        }
        if self.add_dev_attempted
            && !(self.host_preflight_admitted
                && self.control_opened
                && self.required_features_available)
        {
            failures.push(
                "add_dev_attempted requires admitted host, open control, and required features"
                    .to_string(),
            );
        }
        if self.add_dev_completed
            && !(self.host_preflight_admitted
                && self.control_opened
                && self.required_features_available
                && self.add_dev_dev_id.is_some())
        {
            failures.push(
                "add_dev_completed requires admitted host, open control, required features, and device id"
                    .to_string(),
            );
        }
        if self.set_params_completed
            && !(self.set_params_attempted
                && self.add_dev_completed
                && self.set_params_block_size_bytes.is_some()
                && self.set_params_block_count.is_some()
                && self.set_params_dev_sectors.is_some())
        {
            failures.push(
                "set_params_completed requires attempted SET_PARAMS, ADD_DEV completion, and geometry"
                    .to_string(),
            );
        }
        if self.set_params_completed && self.set_params_errno.is_some() {
            failures.push("set_params_completed must not carry set_params_errno".to_string());
        }
        if self.set_params_attempted
            && !self.set_params_completed
            && self.set_params_errno.is_none()
        {
            failures.push("failed SET_PARAMS must carry set_params_errno".to_string());
        }
        if self.data_queue_opened
            && !(self.data_queue_open_attempted
                && self.set_params_completed
                && self.data_queue_path.is_some())
        {
            failures.push(
                "data_queue_opened requires attempted open, SET_PARAMS completion, and path"
                    .to_string(),
            );
        }
        if self.data_queue_opened && self.data_queue_open_errno.is_some() {
            failures.push("data_queue_opened must not carry data_queue_open_errno".to_string());
        }
        if self.data_queue_open_attempted
            && !self.data_queue_opened
            && self.data_queue_open_errno.is_none()
        {
            failures.push("failed data-queue open must carry data_queue_open_errno".to_string());
        }
        if self.fetch_req_submission_completed
            && !(self.fetch_req_submission_attempted
                && self.data_queue_opened
                && self.data_queue_runtime_live_at_start)
        {
            failures.push(
                "fetch_req_submission_completed requires attempted submission and live data-queue runtime"
                    .to_string(),
            );
        }
        if self.fetch_req_all_queue_tag_slots_covered && !self.exact_fetch_req_coverage() {
            failures.push(
                "fetch_req_all_queue_tag_slots_covered must cover the configured queue/tag geometry"
                    .to_string(),
            );
        }

        let start_dev_preconditions_satisfied = self.start_dev_preconditions_satisfied();
        if self.start_dev_attempted && !start_dev_preconditions_satisfied {
            failures.push(
                "START_DEV attempted without complete live queue/tag FETCH_REQ coverage"
                    .to_string(),
            );
        }
        match (
            self.start_dev_attempted,
            self.start_dev_succeeded,
            self.start_dev_state.as_str(),
        ) {
            (true, true, "succeeded") => {}
            (true, false, "refused") => {}
            (false, false, "not_attempted") => {}
            _ => failures.push(
                "start_dev attempted/succeeded booleans must match start_dev_state".to_string(),
            ),
        }
        if self.start_dev_succeeded
            && (!start_dev_preconditions_satisfied
                || self.start_dev_refusal_class.is_some()
                || self.start_dev_errno.is_some())
        {
            failures.push(
                "successful START_DEV must have complete preconditions and no refusal/errno"
                    .to_string(),
            );
        }
        if self.start_dev_attempted
            && !self.start_dev_succeeded
            && self.start_dev_refusal_class.is_none()
        {
            failures.push("refused START_DEV must carry a named refusal class".to_string());
        }
        if !self.start_dev_attempted
            && !start_dev_preconditions_satisfied
            && self.start_dev_refusal_class.is_none()
        {
            failures.push("early START_DEV refusal must carry a named refusal class".to_string());
        }

        if self.service_loop_owned
            && !(self.start_dev_succeeded && start_dev_preconditions_satisfied)
        {
            failures.push(
                "service_loop_owned requires successful START_DEV and complete preconditions"
                    .to_string(),
            );
        }
        if self.start_dev_succeeded && !self.service_loop_owned {
            failures.push("successful START_DEV must bind a daemon-owned service loop".to_string());
        }
        if self.start_dev_succeeded && !self.service_loop_attempted {
            failures
                .push("successful START_DEV must attempt the data-queue service loop".to_string());
        }
        if self.start_dev_succeeded && self.service_loop_completed_iterations == 0 {
            failures.push(
                "successful START_DEV must record at least one service-loop iteration".to_string(),
            );
        }
        if self.service_loop_cqes_processed > 0 && self.service_loop_completed_iterations == 0 {
            failures.push("service_loop_cqes_processed requires completed_iterations".to_string());
        }

        let request_observation_satisfied = self.request_observation_satisfied();
        if self.start_dev_succeeded && !request_observation_satisfied {
            failures.push(
                "successful START_DEV requires one serviced request or a bounded no-request observation"
                    .to_string(),
            );
        }
        if self.first_request_serviced
            && (self.commit_and_fetch_submitted == 0
                || self.service_loop_cqes_processed == 0
                || self.first_request_observation != "serviced_request")
        {
            failures.push(
                "first_request_serviced requires CQE processing, COMMIT_AND_FETCH, and serviced_request observation"
                    .to_string(),
            );
        }
        if self.bounded_no_request_observed
            && (self.commit_and_fetch_submitted != 0
                || self.first_request_observation != "bounded_no_request")
        {
            failures.push(
                "bounded_no_request_observed requires zero COMMIT_AND_FETCH submissions"
                    .to_string(),
            );
        }
        if self.first_request_serviced && self.bounded_no_request_observed {
            failures.push(
                "first_request_serviced and bounded_no_request_observed are mutually exclusive"
                    .to_string(),
            );
        }

        if !self.shutdown_graceful
            && (self.drain_cqes_processed != 0
                || self.drain_iterations != 0
                || self.drain_timed_out
                || self.drain_hung_io_count != 0
                || self.final_flush_completed)
        {
            failures.push(
                "non-graceful shutdown must not report drain or final-flush completion".to_string(),
            );
        }
        if self.drain_cqes_processed > 0 && self.drain_iterations == 0 {
            failures.push("drain_cqes_processed requires drain_iterations".to_string());
        }
        if self.drain_hung_io_count > 0 && !self.shutdown_graceful {
            failures.push("drain_hung_io_count requires graceful shutdown drain".to_string());
        }
        if self.final_flush_completed && !self.shutdown_graceful {
            failures.push("final_flush_completed requires graceful shutdown".to_string());
        }
        if self.stop_dev_succeeded && !self.stop_dev_attempted {
            failures.push("stop_dev_succeeded requires stop_dev_attempted".to_string());
        }
        if self.del_dev_succeeded && !self.del_dev_attempted {
            failures.push("del_dev_succeeded requires del_dev_attempted".to_string());
        }
        if self.del_dev_succeeded && self.del_dev_errno.is_some() {
            failures.push("del_dev_succeeded must not carry del_dev_errno".to_string());
        }
        if self.add_dev_completed && !self.del_dev_attempted {
            failures.push("ADD_DEV completion must report DEL_DEV cleanup attempt".to_string());
        }

        if !failures.is_empty() {
            return Err(failures.join("; "));
        }

        let cleanup_succeeded = self.cleanup_succeeded();
        let claim_state = if !self.start_dev_succeeded {
            "refused"
        } else if !cleanup_succeeded {
            "cleanup_failed"
        } else if self.first_request_serviced {
            "started_request_serviced"
        } else {
            "started_bounded_no_request"
        };
        let failure_class = match claim_state {
            "refused" => self.start_dev_refusal_class.clone(),
            "cleanup_failed" => Some("cleanup_failed".to_string()),
            _ => None,
        };

        Ok(UblkStartedExportAdmissionVerification {
            claim_state,
            failure_class,
            start_dev_preconditions_satisfied,
            request_observation_satisfied,
            cleanup_succeeded,
        })
    }

    #[must_use]
    pub(crate) fn to_json(&self) -> String {
        match self.verify() {
            Ok(verification) => self.to_json_with_verification(&verification),
            Err(message) => {
                self.to_json_with_verification(&UblkStartedExportAdmissionVerification {
                    claim_state: "invalid",
                    failure_class: Some(message),
                    start_dev_preconditions_satisfied: self.start_dev_preconditions_satisfied(),
                    request_observation_satisfied: self.request_observation_satisfied(),
                    cleanup_succeeded: self.cleanup_succeeded(),
                })
            }
        }
    }

    #[must_use]
    fn to_json_with_verification(
        &self,
        verification: &UblkStartedExportAdmissionVerification,
    ) -> String {
        let mut out = String::new();
        out.push_str("{\n");
        out.push_str("  \"report_version\": 1,\n");
        out.push_str("  \"generated_by\": \"tidefs-block-volume-adapter-daemon\",\n");
        out.push_str("  \"claim_ids\": [\n");
        let _ = writeln!(
            out,
            "    \"{}\",",
            UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID
        );
        let _ = writeln!(out, "    \"{}\"", UBLK_COMPLETION_ARTIFACT_CLAIM_ID);
        out.push_str("  ],\n");
        let _ = writeln!(
            out,
            "  \"evidence_class\": \"{}\",",
            UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_EVIDENCE_CLASS
        );
        out.push_str("  \"evidence_scope\": \"bounded started uBLK export admission and daemon-owned data-queue service-loop trace\",\n");
        out.push_str("  \"scenario\": \"qemu-ublk-smoke\",\n");

        out.push_str("  \"queue_geometry\": {\n");
        write_u16_field(&mut out, "nr_hw_queues", self.nr_hw_queues, 4, true);
        write_u16_field(&mut out, "queue_depth", self.queue_depth, 4, false);
        out.push_str("  },\n");

        out.push_str("  \"host_preflight\": {\n");
        write_string_field(&mut out, "kernel_release", &self.kernel_release, 4, true);
        write_bool_field(
            &mut out,
            "host_preflight_admitted",
            self.host_preflight_admitted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "control_open_attempted",
            self.control_open_attempted,
            4,
            true,
        );
        write_bool_field(&mut out, "control_opened", self.control_opened, 4, true);
        write_option_string_field(
            &mut out,
            "control_open_error_class",
            self.control_open_error_class.as_deref(),
            4,
            false,
        );
        out.push_str("  },\n");

        out.push_str("  \"control_chain\": {\n");
        write_bool_field(
            &mut out,
            "feature_probe_attempted",
            self.feature_probe_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "feature_probe_completed",
            self.feature_probe_completed,
            4,
            true,
        );
        write_option_u64_field(&mut out, "feature_mask", self.feature_mask, 4, true);
        write_bool_field(
            &mut out,
            "required_features_available",
            self.required_features_available,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "add_dev_attempted",
            self.add_dev_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "add_dev_completed",
            self.add_dev_completed,
            4,
            true,
        );
        write_option_u32_field(&mut out, "add_dev_dev_id", self.add_dev_dev_id, 4, true);
        write_bool_field(
            &mut out,
            "set_params_attempted",
            self.set_params_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "set_params_completed",
            self.set_params_completed,
            4,
            true,
        );
        write_option_u64_field(
            &mut out,
            "set_params_block_size_bytes",
            self.set_params_block_size_bytes,
            4,
            true,
        );
        write_option_u64_field(
            &mut out,
            "set_params_block_count",
            self.set_params_block_count,
            4,
            true,
        );
        write_option_u64_field(
            &mut out,
            "set_params_dev_sectors",
            self.set_params_dev_sectors,
            4,
            true,
        );
        write_option_i32_field(
            &mut out,
            "set_params_errno",
            self.set_params_errno,
            4,
            false,
        );
        out.push_str("  },\n");

        out.push_str("  \"data_queue\": {\n");
        write_bool_field(
            &mut out,
            "open_attempted",
            self.data_queue_open_attempted,
            4,
            true,
        );
        write_bool_field(&mut out, "opened", self.data_queue_opened, 4, true);
        write_option_string_field(
            &mut out,
            "path",
            self.data_queue_path
                .as_ref()
                .map(|path| path.display().to_string())
                .as_deref(),
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "runtime_live_at_start",
            self.data_queue_runtime_live_at_start,
            4,
            true,
        );
        write_option_i32_field(&mut out, "open_errno", self.data_queue_open_errno, 4, false);
        out.push_str("  },\n");

        out.push_str("  \"fetch_req_coverage\": {\n");
        write_bool_field(
            &mut out,
            "submission_attempted",
            self.fetch_req_submission_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "submission_completed",
            self.fetch_req_submission_completed,
            4,
            true,
        );
        write_u32_field(
            &mut out,
            "required_commands",
            self.fetch_req_required_commands,
            4,
            true,
        );
        write_u32_field(
            &mut out,
            "submitted_commands",
            self.fetch_req_submitted_commands,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "all_queue_tag_slots_covered",
            self.fetch_req_all_queue_tag_slots_covered,
            4,
            true,
        );
        write_option_u16_field(&mut out, "first_qid", self.fetch_req_first_qid, 4, true);
        write_option_u16_field(&mut out, "first_tag", self.fetch_req_first_tag, 4, true);
        write_option_u16_field(&mut out, "last_qid", self.fetch_req_last_qid, 4, true);
        write_option_u16_field(&mut out, "last_tag", self.fetch_req_last_tag, 4, false);
        out.push_str("  },\n");

        out.push_str("  \"start_dev\": {\n");
        write_bool_field(&mut out, "attempted", self.start_dev_attempted, 4, true);
        write_bool_field(&mut out, "succeeded", self.start_dev_succeeded, 4, true);
        write_string_field(&mut out, "state", &self.start_dev_state, 4, true);
        write_option_string_field(
            &mut out,
            "refusal_class",
            self.start_dev_refusal_class.as_deref(),
            4,
            true,
        );
        write_option_i32_field(&mut out, "errno", self.start_dev_errno, 4, false);
        out.push_str("  },\n");

        out.push_str("  \"service_loop\": {\n");
        write_bool_field(&mut out, "owned", self.service_loop_owned, 4, true);
        write_bool_field(&mut out, "attempted", self.service_loop_attempted, 4, true);
        write_u64_field(
            &mut out,
            "completed_iterations",
            self.service_loop_completed_iterations,
            4,
            true,
        );
        write_u64_field(
            &mut out,
            "cqes_processed",
            self.service_loop_cqes_processed,
            4,
            true,
        );
        write_string_field(
            &mut out,
            "first_request_observation",
            &self.first_request_observation,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "first_request_serviced",
            self.first_request_serviced,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "bounded_no_request_observed",
            self.bounded_no_request_observed,
            4,
            true,
        );
        write_u64_field(
            &mut out,
            "commit_and_fetch_submitted",
            self.commit_and_fetch_submitted,
            4,
            false,
        );
        out.push_str("  },\n");

        out.push_str("  \"completion_authority\": {\n");
        write_string_field(
            &mut out,
            "claim_id",
            self.completion_authority_claim_id,
            4,
            true,
        );
        write_string_field(
            &mut out,
            "evidence_class",
            self.completion_authority_evidence_class,
            4,
            true,
        );
        write_string_field(
            &mut out,
            "verifier",
            "tidefs-xtask validate-ublk-completion-artifact",
            4,
            false,
        );
        out.push_str("  },\n");

        out.push_str("  \"cleanup\": {\n");
        write_bool_field(
            &mut out,
            "shutdown_graceful",
            self.shutdown_graceful,
            4,
            true,
        );
        write_u64_field(
            &mut out,
            "drain_cqes_processed",
            self.drain_cqes_processed,
            4,
            true,
        );
        write_u64_field(&mut out, "drain_iterations", self.drain_iterations, 4, true);
        write_bool_field(&mut out, "drain_timed_out", self.drain_timed_out, 4, true);
        write_u64_field(
            &mut out,
            "drain_hung_io_count",
            self.drain_hung_io_count,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "final_flush_completed",
            self.final_flush_completed,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "stop_dev_attempted",
            self.stop_dev_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "stop_dev_succeeded",
            self.stop_dev_succeeded,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "del_dev_attempted",
            self.del_dev_attempted,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "del_dev_succeeded",
            self.del_dev_succeeded,
            4,
            true,
        );
        write_option_i32_field(&mut out, "del_dev_errno", self.del_dev_errno, 4, false);
        out.push_str("  },\n");

        out.push_str("  \"admission_verifier\": {\n");
        write_string_field(
            &mut out,
            "verifier",
            UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_VERIFIER,
            4,
            true,
        );
        write_string_field(&mut out, "claim_state", verification.claim_state, 4, true);
        write_option_string_field(
            &mut out,
            "failure_class",
            verification.failure_class.as_deref(),
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "start_dev_preconditions_satisfied",
            verification.start_dev_preconditions_satisfied,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "request_observation_satisfied",
            verification.request_observation_satisfied,
            4,
            true,
        );
        write_bool_field(
            &mut out,
            "cleanup_succeeded",
            verification.cleanup_succeeded,
            4,
            false,
        );
        out.push_str("  }\n");
        out.push_str("}\n");
        out
    }

    #[must_use]
    fn exact_fetch_req_coverage(&self) -> bool {
        self.fetch_req_submission_completed
            && self.fetch_req_required_commands > 0
            && self.fetch_req_submitted_commands == self.fetch_req_required_commands
            && self.fetch_req_required_commands
                == u32::from(self.nr_hw_queues) * u32::from(self.queue_depth)
            && self.fetch_req_first_qid == Some(0)
            && self.fetch_req_first_tag == Some(0)
            && self.fetch_req_last_qid == Some(self.nr_hw_queues.saturating_sub(1))
            && self.fetch_req_last_tag == Some(self.queue_depth.saturating_sub(1))
            && self.data_queue_runtime_live_at_start
    }

    #[must_use]
    fn start_dev_preconditions_satisfied(&self) -> bool {
        self.host_preflight_admitted
            && self.control_opened
            && self.required_features_available
            && self.add_dev_completed
            && self.set_params_completed
            && self.data_queue_opened
            && self.data_queue_runtime_live_at_start
            && self.fetch_req_all_queue_tag_slots_covered
            && self.exact_fetch_req_coverage()
    }

    #[must_use]
    fn request_observation_satisfied(&self) -> bool {
        if !self.start_dev_succeeded {
            return false;
        }
        self.service_loop_attempted
            && ((self.first_request_serviced
                && !self.bounded_no_request_observed
                && self.commit_and_fetch_submitted > 0
                && self.first_request_observation == "serviced_request")
                || (self.bounded_no_request_observed
                    && !self.first_request_serviced
                    && self.commit_and_fetch_submitted == 0
                    && self.first_request_observation == "bounded_no_request"))
    }

    #[must_use]
    fn cleanup_succeeded(&self) -> bool {
        !self.add_dev_completed
            || (self.del_dev_attempted && self.del_dev_succeeded && self.del_dev_errno.is_none())
    }
}

impl Default for UblkStartedExportAdmissionArtifact {
    fn default() -> Self {
        Self {
            nr_hw_queues: 0,
            queue_depth: 0,
            kernel_release: String::new(),
            host_preflight_admitted: false,
            control_open_attempted: false,
            control_opened: false,
            control_open_error_class: None,
            feature_probe_attempted: false,
            feature_probe_completed: false,
            feature_mask: None,
            required_features_available: false,
            add_dev_attempted: false,
            add_dev_completed: false,
            add_dev_dev_id: None,
            set_params_attempted: false,
            set_params_completed: false,
            set_params_block_size_bytes: None,
            set_params_block_count: None,
            set_params_dev_sectors: None,
            set_params_errno: None,
            data_queue_open_attempted: false,
            data_queue_opened: false,
            data_queue_path: None,
            data_queue_runtime_live_at_start: false,
            data_queue_open_errno: None,
            fetch_req_submission_attempted: false,
            fetch_req_submission_completed: false,
            fetch_req_required_commands: 0,
            fetch_req_submitted_commands: 0,
            fetch_req_all_queue_tag_slots_covered: false,
            fetch_req_first_qid: None,
            fetch_req_first_tag: None,
            fetch_req_last_qid: None,
            fetch_req_last_tag: None,
            start_dev_attempted: false,
            start_dev_succeeded: false,
            start_dev_state: "not_attempted".to_string(),
            start_dev_refusal_class: None,
            start_dev_errno: None,
            service_loop_owned: false,
            service_loop_attempted: false,
            service_loop_completed_iterations: 0,
            service_loop_cqes_processed: 0,
            first_request_observation: "not_started".to_string(),
            first_request_serviced: false,
            bounded_no_request_observed: false,
            commit_and_fetch_submitted: 0,
            completion_authority_claim_id: UBLK_COMPLETION_ARTIFACT_CLAIM_ID,
            completion_authority_evidence_class: UBLK_COMPLETION_ARTIFACT_EVIDENCE_CLASS,
            shutdown_graceful: false,
            drain_cqes_processed: 0,
            drain_iterations: 0,
            drain_timed_out: false,
            drain_hung_io_count: 0,
            final_flush_completed: false,
            stop_dev_attempted: false,
            stop_dev_succeeded: false,
            del_dev_attempted: false,
            del_dev_succeeded: false,
            del_dev_errno: None,
        }
    }
}

fn write_indent(out: &mut String, indent: usize) {
    for _ in 0..indent {
        out.push(' ');
    }
}

fn write_json_string(out: &mut String, value: &str) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            ch if ch.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(ch));
            }
            ch => out.push(ch),
        }
    }
    out.push('"');
}

fn write_field_prefix(out: &mut String, name: &str, indent: usize) {
    write_indent(out, indent);
    write_json_string(out, name);
    out.push_str(": ");
}

fn finish_field(out: &mut String, comma: bool) {
    if comma {
        out.push(',');
    }
    out.push('\n');
}

fn write_string_field(out: &mut String, name: &str, value: &str, indent: usize, comma: bool) {
    write_field_prefix(out, name, indent);
    write_json_string(out, value);
    finish_field(out, comma);
}

fn write_option_string_field(
    out: &mut String,
    name: &str,
    value: Option<&str>,
    indent: usize,
    comma: bool,
) {
    write_field_prefix(out, name, indent);
    match value {
        Some(value) => write_json_string(out, value),
        None => out.push_str("null"),
    }
    finish_field(out, comma);
}

fn write_bool_field(out: &mut String, name: &str, value: bool, indent: usize, comma: bool) {
    write_field_prefix(out, name, indent);
    out.push_str(if value { "true" } else { "false" });
    finish_field(out, comma);
}

fn write_u64_field(out: &mut String, name: &str, value: u64, indent: usize, comma: bool) {
    write_field_prefix(out, name, indent);
    let _ = write!(out, "{value}");
    finish_field(out, comma);
}

fn write_u32_field(out: &mut String, name: &str, value: u32, indent: usize, comma: bool) {
    write_field_prefix(out, name, indent);
    let _ = write!(out, "{value}");
    finish_field(out, comma);
}

fn write_u16_field(out: &mut String, name: &str, value: u16, indent: usize, comma: bool) {
    write_field_prefix(out, name, indent);
    let _ = write!(out, "{value}");
    finish_field(out, comma);
}

fn write_option_u64_field(
    out: &mut String,
    name: &str,
    value: Option<u64>,
    indent: usize,
    comma: bool,
) {
    write_field_prefix(out, name, indent);
    match value {
        Some(value) => {
            let _ = write!(out, "{value}");
        }
        None => out.push_str("null"),
    }
    finish_field(out, comma);
}

fn write_option_u32_field(
    out: &mut String,
    name: &str,
    value: Option<u32>,
    indent: usize,
    comma: bool,
) {
    write_field_prefix(out, name, indent);
    match value {
        Some(value) => {
            let _ = write!(out, "{value}");
        }
        None => out.push_str("null"),
    }
    finish_field(out, comma);
}

fn write_option_u16_field(
    out: &mut String,
    name: &str,
    value: Option<u16>,
    indent: usize,
    comma: bool,
) {
    write_field_prefix(out, name, indent);
    match value {
        Some(value) => {
            let _ = write!(out, "{value}");
        }
        None => out.push_str("null"),
    }
    finish_field(out, comma);
}

fn write_option_i32_field(
    out: &mut String,
    name: &str,
    value: Option<i32>,
    indent: usize,
    comma: bool,
) {
    write_field_prefix(out, name, indent);
    match value {
        Some(value) => {
            let _ = write!(out, "{value}");
        }
        None => out.push_str("null"),
    }
    finish_field(out, comma);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_started_export_artifact() -> UblkStartedExportAdmissionArtifact {
        UblkStartedExportAdmissionArtifact {
            nr_hw_queues: 1,
            queue_depth: 2,
            kernel_release: "7.0.0-test".to_string(),
            host_preflight_admitted: true,
            control_open_attempted: true,
            control_opened: true,
            feature_probe_attempted: true,
            feature_probe_completed: true,
            feature_mask: Some(0xc0),
            required_features_available: true,
            add_dev_attempted: true,
            add_dev_completed: true,
            add_dev_dev_id: Some(0),
            set_params_attempted: true,
            set_params_completed: true,
            set_params_block_size_bytes: Some(4096),
            set_params_block_count: Some(128),
            set_params_dev_sectors: Some(1024),
            data_queue_open_attempted: true,
            data_queue_opened: true,
            data_queue_path: Some(PathBuf::from("/dev/ublkc0")),
            data_queue_runtime_live_at_start: true,
            fetch_req_submission_attempted: true,
            fetch_req_submission_completed: true,
            fetch_req_required_commands: 2,
            fetch_req_submitted_commands: 2,
            fetch_req_all_queue_tag_slots_covered: true,
            fetch_req_first_qid: Some(0),
            fetch_req_first_tag: Some(0),
            fetch_req_last_qid: Some(0),
            fetch_req_last_tag: Some(1),
            start_dev_attempted: true,
            start_dev_succeeded: true,
            start_dev_state: "succeeded".to_string(),
            service_loop_owned: true,
            service_loop_attempted: true,
            service_loop_completed_iterations: 3,
            service_loop_cqes_processed: 4,
            first_request_observation: "serviced_request".to_string(),
            first_request_serviced: true,
            commit_and_fetch_submitted: 1,
            stop_dev_attempted: true,
            stop_dev_succeeded: true,
            del_dev_attempted: true,
            del_dev_succeeded: true,
            ..Default::default()
        }
    }

    #[test]
    fn started_export_artifact_json_records_completion_authority() {
        let artifact = valid_started_export_artifact();
        let json = artifact.to_json();
        assert!(json.contains(UBLK_STARTED_EXPORT_ADMISSION_ARTIFACT_CLAIM_ID));
        assert!(json.contains(UBLK_COMPLETION_ARTIFACT_CLAIM_ID));
        assert!(json.contains("\"first_request_observation\": \"serviced_request\""));
        assert!(json.contains("\"all_queue_tag_slots_covered\": true"));
        assert!(json.contains("\"claim_state\": \"started_request_serviced\""));
    }

    #[test]
    fn verifier_rejects_start_dev_without_live_fetch_coverage() {
        let mut artifact = valid_started_export_artifact();
        artifact.data_queue_runtime_live_at_start = false;
        let error = artifact.verify().expect_err("missing liveness must fail");
        assert!(error.contains("START_DEV attempted without complete live queue/tag"));
    }

    #[test]
    fn verifier_rejects_incomplete_queue_tag_geometry() {
        let mut artifact = valid_started_export_artifact();
        artifact.fetch_req_last_tag = Some(0);
        let error = artifact.verify().expect_err("bad tag coverage must fail");
        assert!(error.contains("configured queue/tag geometry"));
    }

    #[test]
    fn verifier_accepts_cleanup_failed_as_visible_claim_state() {
        let mut artifact = valid_started_export_artifact();
        artifact.del_dev_succeeded = false;
        artifact.del_dev_errno = Some(libc::EBUSY);
        let verification = artifact.verify().expect("cleanup failure is reportable");
        assert_eq!(verification.claim_state, "cleanup_failed");
        assert_eq!(
            verification.failure_class.as_deref(),
            Some("cleanup_failed")
        );
    }

    #[test]
    fn verifier_requires_request_or_bounded_no_request_after_start() {
        let mut artifact = valid_started_export_artifact();
        artifact.first_request_serviced = false;
        artifact.commit_and_fetch_submitted = 0;
        artifact.first_request_observation = "no_request_observation_missing".to_string();
        let error = artifact.verify().expect_err("missing request observation");
        assert!(error.contains("one serviced request or a bounded no-request observation"));
    }
}
